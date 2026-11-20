"""Performance benchmark harness for BlindVault Control Plane.

Measures:
1. Concurrent ECDSA challenge-response handshakes (p50, p95, p99, handshakes/sec).
2. Concurrent authenticated idle WebSocket peers with heartbeats (500 peers).
3. End-to-end encrypted relay streaming throughput (100 MiB).
"""

import asyncio
import json
import secrets
import socket
import time
from typing import Any

import fakeredis.aioredis
import numpy as np
import uvicorn
import websockets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from blindvault_control.crypto import compute_peer_fingerprint, decode_base64, encode_base64
from blindvault_control.main import app
from blindvault_control.rate_limiter import RateLimiter
from blindvault_control.redis_store import RedisStore
from blindvault_control.relay import RelayManager
from blindvault_control.signaling import SignalingManager


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


async def start_benchmark_server(
    port: int,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> uvicorn.Server:
    test_redis_store = RedisStore(client=fake_redis)
    test_rate_limiter = RateLimiter(fake_redis)
    test_signaling = SignalingManager()
    test_relay = RelayManager(test_redis_store)

    app.state.redis_store = test_redis_store
    app.state.rate_limiter = test_rate_limiter
    test_rate_limiter.check_handshake = lambda _ip: asyncio.sleep(0, result=True)  # type: ignore[assignment]
    test_rate_limiter.check_invite = lambda _fp: asyncio.sleep(0, result=True)  # type: ignore[assignment]
    test_rate_limiter.check_relay = lambda _fp: asyncio.sleep(0, result=True)  # type: ignore[assignment]

    app.state.signaling_manager = test_signaling
    app.state.relay_manager = test_relay

    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        log_level="error",
        ws_max_size=262144,
    )
    server = uvicorn.Server(config)
    asyncio.create_task(server.serve())

    while not server.started:
        await asyncio.sleep(0.02)
    return server


async def benchmark_handshakes(
    base_ws_url: str,
    total_handshakes: int = 500,
    concurrency: int = 25,
) -> dict[str, float]:
    print(
        f"\n[1/3] Benchmarking {total_handshakes} ECDSA challenge-response handshakes "
        f"({concurrency} concurrent workers)..."
    )

    keypairs = []
    for _ in range(concurrency):
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key()
        pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        keypairs.append((priv, pem))

    latencies: list[float] = []
    queue: asyncio.Queue[int] = asyncio.Queue()
    for i in range(total_handshakes):
        queue.put_nowait(i)

    async def worker(worker_id: int) -> None:
        priv, pem = keypairs[worker_id % len(keypairs)]
        while not queue.empty():
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                break

            t0 = time.perf_counter()
            async with websockets.connect(f"{base_ws_url}/ws/control") as ws:
                await ws.send(json.dumps({"type": "HELLO", "public_key": pem}))
                raw_ch = await ws.recv()
                ch = json.loads(raw_ch)
                nonce = decode_base64(ch["nonce"])
                sig = priv.sign(nonce, ec.ECDSA(hashes.SHA256()))
                await ws.send(json.dumps({"type": "AUTH", "signature": encode_base64(sig)}))
                raw_ok = await ws.recv()
                ok = json.loads(raw_ok)
                assert ok["type"] == "AUTH_OK"

            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            latencies.append(elapsed_ms)
            queue.task_done()

    t_start = time.perf_counter()
    workers = [asyncio.create_task(worker(i)) for i in range(concurrency)]
    await asyncio.gather(*workers)
    total_time = time.perf_counter() - t_start

    arr = np.array(latencies)
    p50 = float(np.percentile(arr, 50))
    p95 = float(np.percentile(arr, 95))
    p99 = float(np.percentile(arr, 99))
    rate = total_handshakes / total_time

    return {
        "p50_ms": p50,
        "p95_ms": p95,
        "p99_ms": p99,
        "rate_per_sec": rate,
        "total_time_s": total_time,
    }


async def benchmark_concurrent_peers(
    base_ws_url: str,
    num_peers: int = 500,
) -> dict[str, Any]:
    print(f"\n[2/3] Benchmarking {num_peers} concurrent authenticated WebSocket peer sessions...")

    keypairs = []
    for _ in range(num_peers):
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key()
        pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        keypairs.append((priv, pem))

    connections: list[Any] = []

    batch_size = 50
    for idx in range(0, num_peers, batch_size):
        sub_batch = keypairs[idx : idx + batch_size]

        async def connect_one(pair: tuple[Any, str]) -> Any:
            priv, pem = pair
            ws = await websockets.connect(f"{base_ws_url}/ws/control")
            await ws.send(json.dumps({"type": "HELLO", "public_key": pem}))
            ch = json.loads(await ws.recv())
            sig = priv.sign(decode_base64(ch["nonce"]), ec.ECDSA(hashes.SHA256()))
            await ws.send(json.dumps({"type": "AUTH", "signature": encode_base64(sig)}))
            ok = json.loads(await ws.recv())
            assert ok["type"] == "AUTH_OK"
            return ws

        results = await asyncio.gather(*(connect_one(p) for p in sub_batch))
        connections.extend(results)

    print(f"      Successfully connected and authenticated {len(connections)} peers.")

    t_start = time.perf_counter()

    async def ping_one(ws: Any) -> float:
        t0 = time.perf_counter()
        await ws.send(json.dumps({"type": "PING"}))
        pong = json.loads(await ws.recv())
        assert pong["type"] == "PONG"
        return (time.perf_counter() - t0) * 1000.0

    ping_times = await asyncio.gather(*(ping_one(ws) for ws in connections))
    total_ping_time = time.perf_counter() - t_start

    arr = np.array(ping_times)
    p50 = float(np.percentile(arr, 50))
    p95 = float(np.percentile(arr, 95))
    p99 = float(np.percentile(arr, 99))

    for ws in connections:
        await ws.close()

    return {
        "active_peers": len(connections),
        "fanout_ping_total_s": total_ping_time,
        "ping_p50_ms": p50,
        "ping_p95_ms": p95,
        "ping_p99_ms": p99,
    }


async def benchmark_relay_throughput(
    base_ws_url: str,
    total_mib: int = 100,
) -> dict[str, float]:
    print(f"\n[3/3] Benchmarking encrypted fallback relay throughput ({total_mib} MiB stream)...")

    priv_a = ec.generate_private_key(ec.SECP256R1())
    pem_a = (
        priv_a.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )

    priv_b = ec.generate_private_key(ec.SECP256R1())
    pem_b = (
        priv_b.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    fp_b = compute_peer_fingerprint(priv_b.public_key())

    async with (
        websockets.connect(f"{base_ws_url}/ws/control") as ws_a,
        websockets.connect(f"{base_ws_url}/ws/control") as ws_b,
    ):
        # Auth A
        await ws_a.send(json.dumps({"type": "HELLO", "public_key": pem_a}))
        ch_a = json.loads(await ws_a.recv())
        sig_a = priv_a.sign(decode_base64(ch_a["nonce"]), ec.ECDSA(hashes.SHA256()))
        await ws_a.send(json.dumps({"type": "AUTH", "signature": encode_base64(sig_a)}))
        assert json.loads(await ws_a.recv())["type"] == "AUTH_OK"

        # Auth B
        await ws_b.send(json.dumps({"type": "HELLO", "public_key": pem_b}))
        ch_b = json.loads(await ws_b.recv())
        sig_b = priv_b.sign(decode_base64(ch_b["nonce"]), ec.ECDSA(hashes.SHA256()))
        await ws_b.send(json.dumps({"type": "AUTH", "signature": encode_base64(sig_b)}))
        assert json.loads(await ws_b.recv())["type"] == "AUTH_OK"

        # Request Relay
        await ws_a.send(json.dumps({"type": "CREATE_RELAY", "target_fingerprint": fp_b}))
        created = json.loads(await ws_a.recv())
        session_id = created["session_id"]
        token_a = created["token"]
        token_b = json.loads(await ws_b.recv())["token"]

    url_a = f"{base_ws_url}/ws/relay/{session_id}?token={token_a}"
    url_b = f"{base_ws_url}/ws/relay/{session_id}?token={token_b}"

    chunk_size = 64 * 1024  # 64 KiB chunks
    total_bytes = total_mib * 1024 * 1024
    num_chunks = total_bytes // chunk_size
    sample_chunk = secrets.token_bytes(chunk_size)

    async with (
        websockets.connect(url_a, max_size=131072) as relay_a,
        websockets.connect(url_b, max_size=131072) as relay_b,
    ):
        received_bytes = 0

        async def receiver() -> None:
            nonlocal received_bytes
            while received_bytes < total_bytes:
                data = await relay_b.recv()
                received_bytes += len(data)

        t_start = time.perf_counter()
        recv_task = asyncio.create_task(receiver())

        for _ in range(num_chunks):
            await relay_a.send(sample_chunk)

        await recv_task
        elapsed_s = time.perf_counter() - t_start

    speed_mibs = float(total_mib) / elapsed_s
    speed_mbps = (float(total_bytes) * 8.0 / (1000 * 1000)) / elapsed_s

    return {
        "total_mib": float(total_mib),
        "elapsed_s": elapsed_s,
        "throughput_mib_s": speed_mibs,
        "throughput_mbps": speed_mbps,
    }


async def main() -> None:
    port = get_free_port()
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    server = await start_benchmark_server(port, fake_redis)
    base_ws_url = f"ws://127.0.0.1:{port}"

    try:
        hs_res = await benchmark_handshakes(base_ws_url, total_handshakes=500, concurrency=25)
        peer_res = await benchmark_concurrent_peers(base_ws_url, num_peers=500)
        relay_res = await benchmark_relay_throughput(base_ws_url, total_mib=100)

        rate_val = f"{hs_res['rate_per_sec']:>10.2f} handshakes/s"
        hs_p50 = f"{hs_res['p50_ms']:>10.2f} ms"
        hs_p95 = f"{hs_res['p95_ms']:>10.2f} ms"
        hs_p99 = f"{hs_res['p99_ms']:>10.2f} ms"
        peers_val = f"{peer_res['active_peers']:>10} peers"
        p_p50 = f"{peer_res['ping_p50_ms']:>10.2f} ms"
        p_p95 = f"{peer_res['ping_p95_ms']:>10.2f} ms"
        p_p99 = f"{peer_res['ping_p99_ms']:>10.2f} ms"
        t_mibs = f"{relay_res['throughput_mib_s']:>10.2f} MiB/s"
        t_mbps = f"{relay_res['throughput_mbps']:>10.2f} Mbps"
        t_sec = f"{relay_res['elapsed_s']:>10.2f} s"

        def row(m: str, w: str, r: str) -> None:
            print(f"{m:<44} | {w:<15} | {r}")

        print("\n" + "=" * 90)
        print("BLINDVAULT-CONTROL BENCHMARK RESULTS")
        print("=" * 90)
        row("Benchmark Metric", "Workload", "Result")
        print("-" * 90)
        row("ECDSA Challenge-Response Handshakes/sec", "500 total", rate_val)
        row("Handshake Latency p50", "25 workers", hs_p50)
        row("Handshake Latency p95", "25 workers", hs_p95)
        row("Handshake Latency p99", "25 workers", hs_p99)
        print("-" * 90)
        row("Concurrent Authenticated WS Sessions", "Zero-knowledge", peers_val)
        row("Fan-out Heartbeat Ping Latency p50", "500 peers", p_p50)
        row("Fan-out Heartbeat Ping Latency p95", "500 peers", p_p95)
        row("Fan-out Heartbeat Ping Latency p99", "500 peers", p_p99)
        print("-" * 90)
        row("Encrypted Fallback Relay Throughput", "100 MiB / 64KiB", t_mibs)
        row("Encrypted Fallback Relay Bandwidth", "100 MiB stream", t_mbps)
        row("Relay Transfer Elapsed Time", "100 MiB stream", t_sec)
        print("=" * 90 + "\n")

    finally:
        server.should_exit = True
        await asyncio.sleep(0.1)
        await fake_redis.aclose()


if __name__ == "__main__":
    asyncio.run(main())
