(() => {
  "use strict";

  const CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

  function copyTextWithFeedback(text, buttonEl, labelEl) {
    if (!text) return;
    const finish = () => {
      if (buttonEl) buttonEl.classList.add("is-copied");
      if (labelEl) labelEl.textContent = "Copied \u2713";
      window.setTimeout(() => {
        if (buttonEl) buttonEl.classList.remove("is-copied");
        if (labelEl) labelEl.textContent = "Copy";
      }, 1600);
    };

    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(finish).catch(() => fallbackCopy(text, finish));
    } else {
      fallbackCopy(text, finish);
    }
  }

  function fallbackCopy(text, done) {
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    try {
      document.execCommand("copy");
    } catch (_) {
      // Ignore if browser restricts clipboard access
    }
    document.body.removeChild(area);
    done();
  }

  // 1. Mobile Navigation Drawer & Header Control Switcher
  const menuBtn = document.getElementById("mobile-menu-btn");
  const drawer = document.getElementById("mobile-drawer");
  if (menuBtn && drawer) {
    menuBtn.addEventListener("click", () => {
      const open = menuBtn.getAttribute("aria-expanded") === "true";
      menuBtn.setAttribute("aria-expanded", String(!open));
      drawer.hidden = open;
    });
    drawer.querySelectorAll("a").forEach((link) => {
      link.addEventListener("click", () => {
        menuBtn.setAttribute("aria-expanded", "false");
        drawer.hidden = true;
      });
    });
  }

  const switcher = document.querySelector(".product-switcher");
  if (switcher) {
    const thumb = switcher.querySelector(".switch-thumb");
    const switchPills = Array.from(switcher.querySelectorAll(".switch-pill"));
    const initialProduct = switcher.dataset.active || "control";
    let navigating = false;

    const positionThumb = (pill, instant) => {
      if (!pill || !thumb) return;
      if (instant) switcher.classList.add("no-anim");
      thumb.style.width = `${pill.offsetWidth}px`;
      thumb.style.transform = `translateX(${pill.offsetLeft}px)`;
      switcher.classList.add("is-ready");
      if (instant) {
        void thumb.offsetWidth;
        switcher.classList.remove("no-anim");
      }
    };

    const resetToInitial = () => {
      navigating = false;
      let activePill = null;
      switchPills.forEach((pill) => {
        const isCurrent = pill.dataset.product === initialProduct;
        pill.classList.toggle("is-active", isCurrent);
        if (isCurrent) {
          pill.setAttribute("aria-current", "page");
          activePill = pill;
        } else {
          pill.removeAttribute("aria-current");
        }
      });
      positionThumb(activePill, true);
    };

    resetToInitial();
    window.addEventListener("resize", () => {
      positionThumb(switcher.querySelector(".switch-pill.is-active"), true);
    });
    window.addEventListener("pageshow", resetToInitial);
    document.fonts?.ready?.then(() => {
      positionThumb(switcher.querySelector(".switch-pill.is-active"), true);
    });

    switchPills.forEach((pill) => {
      pill.addEventListener("click", (e) => {
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) {
          return;
        }
        e.preventDefault();
        if (pill.dataset.product === initialProduct) {
          document.getElementById("top")?.scrollIntoView({ behavior: "smooth" });
          return;
        }
        if (navigating) return;
        navigating = true;

        switchPills.forEach((p) => {
          const active = p === pill;
          p.classList.toggle("is-active", active);
          if (active) {
            p.setAttribute("aria-current", "page");
          } else {
            p.removeAttribute("aria-current");
          }
        });
        positionThumb(pill, false);

        const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        if (reduceMotion) {
          window.location.assign(pill.href);
        } else {
          window.setTimeout(() => {
            window.location.assign(pill.href);
          }, 200);
        }
      });
    });
  }

  // 2. Hero 3-Node Topology Switcher
  const topoPills = Array.from(document.querySelectorAll(".topo-pill"));
  const topoStage = document.getElementById("topo-stage");
  const topoPathLabel = document.getElementById("topo-path-label");
  const telemetryPath = document.getElementById("telemetry-path");
  const telemetryGuard = document.getElementById("telemetry-guard");
  const telemetryVisibility = document.getElementById("telemetry-visibility");
  const heroCycleStatus = document.getElementById("hero-cycle-status");

  const TOPO_STATES = {
    direct: {
      badge: "Direct mTLS 1.3 P2P Tunnel",
      path: "Direct UDP/TCP Hole-Punch",
      guard: "Ed25519 Signed BVST (:3478)",
      visibility: "Signal Hints Only \u2022 0 Keys"
    },
    relay: {
      badge: "Opaque 64 KiB Binary Fallback",
      path: "WS /ws/relay/{session_id} Bridge",
      guard: "Binary Only \u2022 \u2264 64 KiB (1003/1009)",
      visibility: "Opaque mTLS 1.3 Ciphertext"
    }
  };

  let topoMode = "direct";
  let topoTimer = null;

  function setTopologyMode(mode) {
    const config = TOPO_STATES[mode];
    if (!config) return;
    topoMode = mode;

    topoPills.forEach((pill) => {
      const active = pill.dataset.topoMode === mode;
      pill.classList.toggle("is-active", active);
      pill.setAttribute("aria-selected", String(active));
    });

    if (topoStage) topoStage.setAttribute("data-mode", mode);
    if (topoPathLabel) topoPathLabel.textContent = config.badge;
    if (telemetryPath) telemetryPath.textContent = config.path;
    if (telemetryGuard) telemetryGuard.textContent = config.guard;
    if (telemetryVisibility) telemetryVisibility.textContent = config.visibility;
  }

  function startTopoCycle() {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    if (topoTimer) window.clearInterval(topoTimer);
    topoTimer = window.setInterval(() => {
      setTopologyMode(topoMode === "direct" ? "relay" : "direct");
    }, 4200);
  }

  topoPills.forEach((pill) => {
    pill.addEventListener("click", () => {
      if (topoTimer) {
        window.clearInterval(topoTimer);
        topoTimer = null;
      }
      if (heroCycleStatus) heroCycleStatus.textContent = "Interactive";
      setTopologyMode(pill.dataset.topoMode || "direct");
    });
  });
  startTopoCycle();

  // 3. Interactive 4-Step Connection Walkthrough
  const stepTabs = Array.from(document.querySelectorAll(".step-tab"));
  const stepPanels = Array.from(document.querySelectorAll(".step-visual-pane"));
  const stepCodeRoute = document.getElementById("step-code-route");
  const stepJsonCode = document.getElementById("step-json-code");
  const copyStepBtn = document.getElementById("copy-step-json-btn");
  const copyStepLabel = document.getElementById("copy-step-label");
  const genCrockfordBtn = document.getElementById("gen-crockford-btn");
  const crockfordTicket = document.getElementById("crockford-ticket");

  let activeStep = "auth";
  let sampleInviteCode = "K7M9P3Q2";

  function buildPairingJson(code) {
    return [
      "// 1. Creator -> Server (10 invites/min rate limit)",
      JSON.stringify(
        {
          type: "CREATE_INVITE",
          endpoints: [{ ip: "198.51.100.42", port: 51820, proto: "udp" }]
        },
        null,
        2
      ),
      "",
      "// 2. Server -> Creator (Redis key invite:" + code + " TTL 300s)",
      JSON.stringify(
        {
          type: "INVITE_CREATED",
          code: code,
          ttl: 300
        },
        null,
        2
      ),
      "",
      "// 3. Claimer -> Server (Atomic GETDEL + Zero Self-Pairing)",
      JSON.stringify(
        {
          type: "CLAIM_INVITE",
          code: code,
          endpoints: [{ ip: "203.0.113.19", port: 54012, proto: "udp" }]
        },
        null,
        2
      )
    ].join("\n");
  }

  const STEP_CODE_DATA = {
    auth: {
      route: "WS /ws/control — EC P-256 Auth Sequence",
      code: () =>
        [
          "// 1. Client -> Server (SECP256R1 strictly enforced)",
          JSON.stringify(
            {
              type: "HELLO",
              public_key: "-----BEGIN PUBLIC KEY-----\\nMFkwEwYH...\\n-----END PUBLIC KEY-----",
              observed_endpoint: "198.51.100.42:51820"
            },
            null,
            2
          ),
          "",
          "// 2. Server -> Client (Redis nonce:{fingerprint} TTL 30s)",
          JSON.stringify(
            {
              type: "CHALLENGE",
              nonce: "rQ9m2J5sLwP8xV1kN4cT7yB0hD6fG3jA8zE2uK9wR1M=",
              fingerprint: "a19f4c82d0b3e7149a6c5d128f4e3b09c7d8a6f5e4d3c2b1a0987654321f8e04"
            },
            null,
            2
          ),
          "",
          "// 3. Client -> Server -> AUTH_OK (Consumed once via GETDEL)",
          JSON.stringify(
            {
              type: "AUTH",
              signature: "MEUCIQDx4vB9n7K2aZ8qR..."
            },
            null,
            2
          ),
          JSON.stringify(
            {
              type: "AUTH_OK",
              fingerprint: "a19f4c82d0b3e7149a6c5d128f4e3b09c7d8a6f5e4d3c2b1a0987654321f8e04",
              heartbeat_interval_sec: 20
            },
            null,
            2
          )
        ].join("\n")
    },
    pairing: {
      route: "WS /ws/control — Ephemeral Crockford Invite",
      code: () => buildPairingJson(sampleInviteCode)
    },
    udp: {
      route: "UDP :3478 & /api/v1/info — Signed NAT Discovery",
      code: () =>
        [
          "// GET /api/v1/info (Ed25519 Reflector Key Discovery)",
          JSON.stringify(
            {
              version: "1.0.0",
              udp_reflector_port: 3478,
              udp_reflector_public_key: "4nX9kP2mL8qT1vR7wZ5cB3jF6hN0dY8aE2sU9gK4xM0=",
              udp_reflector_signature_alg: "ed25519",
              supported_curves: ["secp256r1"],
              max_relay_frame_bytes: 65536,
              max_control_frame_bytes: 8192
            },
            null,
            2
          ),
          "",
          "// Forward Verified Candidates Between Matched Peers",
          JSON.stringify(
            {
              type: "HOLE_PUNCH_SYNC",
              target_fingerprint: "7c4209b1e5a3...",
              stage: "punch_ready",
              timestamp: 1795367120.425
            },
            null,
            2
          )
        ].join("\n")
    },
    relay: {
      route: "WS /ws/relay/{session_id} — Opaque Fallback Tunnel",
      code: () =>
        [
          "// 1. Initiator -> Server (5 relays/min Lua token bucket)",
          JSON.stringify(
            {
              type: "CREATE_RELAY",
              target_fingerprint: "7c4209b1e5a3..."
            },
            null,
            2
          ),
          "",
          "// 2. Server -> Initiator (Single-use Bearer token, 30s TTL)",
          JSON.stringify(
            {
              type: "RELAY_CREATED",
              session_id: "rel_9f3c2a8b14e0",
              token: "tok_init_8xL9mQ2vP7..."
            },
            null,
            2
          ),
          "",
          "// 3. Both Peers Connect Over Binary-Only WebSocket",
          "GET /ws/relay/rel_9f3c2a8b14e0 HTTP/1.1",
          "Authorization: Bearer tok_init_8xL9mQ2vP7...",
          "# Close codes: 1003 on text frame | 1009 if frame > 65536 B"
        ].join("\n")
    }
  };

  function setActiveStep(stepKey) {
    const entry = STEP_CODE_DATA[stepKey];
    if (!entry) return;
    activeStep = stepKey;

    stepTabs.forEach((tab) => {
      const active = tab.dataset.step === stepKey;
      tab.classList.toggle("is-active", active);
      tab.setAttribute("aria-selected", String(active));
    });

    stepPanels.forEach((panel) => {
      const active = panel.dataset.stepPanel === stepKey;
      panel.hidden = !active;
      panel.classList.toggle("is-active", active);
    });

    if (stepCodeRoute) stepCodeRoute.textContent = entry.route;
    if (stepJsonCode) stepJsonCode.textContent = entry.code();
  }

  stepTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      setActiveStep(tab.dataset.step || "auth");
    });
  });

  if (copyStepBtn) {
    copyStepBtn.addEventListener("click", () => {
      copyTextWithFeedback(stepJsonCode ? stepJsonCode.textContent || "" : "", copyStepBtn, copyStepLabel);
    });
  }

  function generateCrockfordSample() {
    let raw = "";
    const bytes = new Uint8Array(8);
    if (window.crypto && typeof window.crypto.getRandomValues === "function") {
      window.crypto.getRandomValues(bytes);
    } else {
      for (let i = 0; i < 8; i += 1) {
        bytes[i] = Math.floor(Math.random() * 256);
      }
    }
    for (let i = 0; i < 8; i += 1) {
      raw += CROCKFORD_ALPHABET[bytes[i] % CROCKFORD_ALPHABET.length];
    }
    sampleInviteCode = raw;
    if (crockfordTicket) {
      crockfordTicket.textContent = raw.slice(0, 4) + "-" + raw.slice(4);
    }
    if (activeStep === "pairing" && stepJsonCode) {
      stepJsonCode.textContent = buildPairingJson(sampleInviteCode);
    }
  }

  if (genCrockfordBtn) {
    genCrockfordBtn.addEventListener("click", generateCrockfordSample);
  }

  // Initialize Step 1 JSON
  setActiveStep("auth");

  // 4. Interactive Wire Protocol & UDP Packet Explorer
  const PROTOCOL_ITEMS = [
    {
      id: "HELLO",
      category: "auth",
      categoryLabel: "Auth",
      direction: "Client \u2192 Server",
      route: "WS /ws/control",
      limits: ["10 handshakes/min (IP)", "8 KiB max frame", "SECP256R1 only"],
      description:
        "Initiates mutual challenge authentication by submitting a PEM or DER EC P-256 public key. Non-EC keys and alternate curves (secp256k1, secp384r1, RSA) are rejected before fingerprinting.",
      fields: [
        { name: "type", type: 'Literal["HELLO"]' },
        { name: "public_key", type: "str (PEM / DER EC P-256)" },
        { name: "observed_endpoint", type: "str | None (optional)" }
      ],
      json: {
        type: "HELLO",
        public_key: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----",
        observed_endpoint: "198.51.100.42:51820"
      },
      keywords: "ec p256 secp256r1 curve confusion fingerprint pem der auth hello"
    },
    {
      id: "CHALLENGE",
      category: "auth",
      categoryLabel: "Auth",
      direction: "Server \u2192 Client",
      route: "WS /ws/control",
      limits: ["32B secrets nonce", "Redis 30s TTL", "Single-use GETDEL"],
      description:
        "Server returns a cryptographically random 32-byte base64 nonce stored at nonce:{fingerprint} with a 30s TTL alongside the derived lowercase SHA-256 fingerprint.",
      fields: [
        { name: "type", type: 'Literal["CHALLENGE"]' },
        { name: "nonce", type: "str (base64, 32 bytes)" },
        { name: "fingerprint", type: "str (64-char sha256 hex)" }
      ],
      json: {
        type: "CHALLENGE",
        nonce: "rQ9m2J5sLwP8xV1kN4cT7yB0hD6fG3jA8zE2uK9wR1M=",
        fingerprint: "a19f4c82d0b3e7149a6c5d128f4e3b09c7d8a6f5e4d3c2b1a0987654321f8e04"
      },
      keywords: "nonce getdel replay challenge ttl 30s base64"
    },
    {
      id: "AUTH",
      category: "auth",
      categoryLabel: "Auth",
      direction: "Client \u2192 Server",
      route: "WS /ws/control",
      limits: ["ECDSA-SHA256", "Atomic GETDEL", "Zero Replay"],
      description:
        "Completes authentication by signing the raw decoded 32-byte challenge nonce with the peer's EC P-256 private key. Server consumes the Redis nonce atomically via GETDEL so replay is impossible.",
      fields: [
        { name: "type", type: 'Literal["AUTH"]' },
        { name: "signature", type: "str (base64 ECDSA-SHA256)" }
      ],
      json: {
        type: "AUTH",
        signature: "MEUCIQDx4vB9n7K2aZ8qR5uK1wT9mP4xB2dG7nS3hL6cV2wIgR8tM..."
      },
      keywords: "ecdsa sha256 signature auth getdel replay verify"
    },
    {
      id: "AUTH_OK",
      category: "auth",
      categoryLabel: "Auth",
      direction: "Server \u2192 Client",
      route: "WS /ws/control",
      limits: ["presence TTL 60s", "20s PING interval", "Pub/Sub bv:peer:{fp}"],
      description:
        "Confirms authentication, registers peer presence in Redis with a 60s TTL refreshed by PING/PONG heartbeats every 20s, and subscribes this replica to bv:peer:{fingerprint}.",
      fields: [
        { name: "type", type: 'Literal["AUTH_OK"]' },
        { name: "fingerprint", type: "str" },
        { name: "heartbeat_interval_sec", type: "int = 20" }
      ],
      json: {
        type: "AUTH_OK",
        fingerprint: "a19f4c82d0b3e7149a6c5d128f4e3b09c7d8a6f5e4d3c2b1a0987654321f8e04",
        heartbeat_interval_sec: 20
      },
      keywords: "presence heartbeat ping pong 20s 60s pubsub"
    },
    {
      id: "CREATE_INVITE",
      category: "pairing",
      categoryLabel: "Pairing",
      direction: "Client \u2192 Server",
      route: "WS /ws/control",
      limits: ["10 invites/min (fp)", "300s Redis TTL", "Crockford Base32"],
      description:
        "Requests an ephemeral 8-character Crockford Base32 invite code stored at invite:{code} with a 300s TTL. Responds with INVITE_CREATED carrying the code and TTL.",
      fields: [
        { name: "type", type: 'Literal["CREATE_INVITE"]' },
        { name: "endpoints", type: "list[dict[str, Any]] (default [])" }
      ],
      json: {
        type: "CREATE_INVITE",
        endpoints: [
          { ip: "198.51.100.42", port: 51820, proto: "udp" }
        ]
      },
      keywords: "invite crockford base32 pairing create_invite endpoints 300s"
    },
    {
      id: "CLAIM_INVITE",
      category: "pairing",
      categoryLabel: "Pairing",
      direction: "Client \u2192 Server",
      route: "WS /ws/control",
      limits: ["10 claims/min (fp & IP)", "Single-use GETDEL", "Self-pair blocked"],
      description:
        "Normalizes and atomically consumes invite:{code} via GETDEL. Validates against self-pairing and emits mutual PEER_MATCHED messages without leaking server-observed client_ip.",
      fields: [
        { name: "type", type: 'Literal["CLAIM_INVITE"]' },
        { name: "code", type: "str (8-char Crockford Base32)" },
        { name: "endpoints", type: "list[dict[str, Any]] (default [])" }
      ],
      json: {
        type: "CLAIM_INVITE",
        code: "K7M9-P3Q2",
        endpoints: [
          { ip: "203.0.113.19", port: 54012, proto: "udp" }
        ]
      },
      keywords: "claim redeem crockford rate limit getdel self-pairing"
    },
    {
      id: "PEER_MATCHED",
      category: "pairing",
      categoryLabel: "Pairing",
      direction: "Server \u2192 Both Peers",
      route: "WS /ws/control (or bv:peer:{fp})",
      limits: ["Zero server IP leak", "Cross-replica safe", "Single-use trigger"],
      description:
        "Delivered simultaneously to both creator and claimer (including across distinct replicas via Redis Pub/Sub). Endpoints contain strictly client-declared hints, never server-observed client_ip.",
      fields: [
        { name: "type", type: 'Literal["PEER_MATCHED"]' },
        { name: "peer_fingerprint", type: "str" },
        { name: "endpoints", type: "list[dict[str, Any]]" },
        { name: "role", type: 'Literal["creator", "claimer"]' }
      ],
      json: {
        type: "PEER_MATCHED",
        peer_fingerprint: "7c4209b1e5a3d847f6e2c1b0a987654321fedcba9876543210abcdef12343d19",
        endpoints: [
          { ip: "203.0.113.19", port: 54012, proto: "udp" }
        ],
        role: "creator"
      },
      keywords: "matched mutual creator claimer endpoints zero ip leak pubsub"
    },
    {
      id: "SIGNAL_OFFER",
      category: "signaling",
      categoryLabel: "Signaling",
      direction: "Client \u2194 Client",
      route: "WS /ws/control (routed)",
      limits: ["Opaque forwarding", "Paired SIGNAL_ANSWER identical schema", "Cross-replica bv:peer:*"],
      description:
        "Forwards opaque P2P/ICE session descriptions or UDP candidate descriptors from sender to target_fingerprint. Responder replies using SIGNAL_ANSWER with the exact same payload fields.",
      fields: [
        { name: "type", type: 'Literal["SIGNAL_OFFER"] | "SIGNAL_ANSWER"' },
        { name: "target_fingerprint", type: "str" },
        { name: "session_id", type: "str" },
        { name: "candidate", type: "dict[str, Any]" }
      ],
      json: {
        type: "SIGNAL_OFFER",
        target_fingerprint: "7c4209b1e5a3d847f6e2c1b0a987654321fedcba9876543210abcdef12343d19",
        session_id: "p2p_4d81c2e7",
        candidate: {
          ip: "198.51.100.42",
          port: 51820,
          transport: "udp",
          bvs_signature: "base64-ed25519..."
        }
      },
      keywords: "signal_offer signal_answer ice candidate p2p forwarding"
    },
    {
      id: "HOLE_PUNCH_SYNC",
      category: "signaling",
      categoryLabel: "Signaling",
      direction: "Client \u2194 Client",
      route: "WS /ws/control (routed)",
      limits: ["Synchronized punch window", "Forwarded over bv:peer:{fp}"],
      description:
        "Coordinates synchronized NAT hole-punching timing between paired peers by relaying stage state and optional floating-point timestamp over the low-latency control channel.",
      fields: [
        { name: "type", type: 'Literal["HOLE_PUNCH_SYNC"]' },
        { name: "target_fingerprint", type: "str" },
        { name: "stage", type: "str" },
        { name: "timestamp", type: "float | None (optional)" }
      ],
      json: {
        type: "HOLE_PUNCH_SYNC",
        target_fingerprint: "7c4209b1e5a3d847f6e2c1b0a987654321fedcba9876543210abcdef12343d19",
        stage: "punch_ready",
        timestamp: 1795367120.425
      },
      keywords: "hole punch sync udp tcp nat traversal timing"
    },
    {
      id: "CREATE_RELAY",
      category: "relay",
      categoryLabel: "Relay",
      direction: "Client \u2192 Server",
      route: "WS /ws/control",
      limits: ["5 relays/min (fp)", "30s token TTL", "900s session max"],
      description:
        "Requests an encrypted fallback relay when direct NAT traversal fails. Issues separate single-use tokens bound to (initiator, responder), returning RELAY_CREATED to the caller and forwarding RELAY_INVITE to the target.",
      fields: [
        { name: "type", type: 'Literal["CREATE_RELAY"]' },
        { name: "target_fingerprint", type: "str" }
      ],
      json: {
        type: "CREATE_RELAY",
        target_fingerprint: "7c4209b1e5a3d847f6e2c1b0a987654321fedcba9876543210abcdef12343d19"
      },
      keywords: "relay fallback create_relay relay_created rate limit 5/min"
    },
    {
      id: "RELAY_INVITE",
      category: "relay",
      categoryLabel: "Relay",
      direction: "Server \u2192 Target Peer",
      route: "WS /ws/control + /ws/relay/{session_id}",
      limits: ["Binary only (1003 on text)", "Max 64 KiB (1009)", "Missing/invalid token (1008)", "30s idle timeout"],
      description:
        "Delivers the responder's single-use relay token and session_id. Both peers then connect to WS /ws/relay/{session_id} (via Authorization: Bearer <token>, X-Relay-Token, or ?token=) to stream opaque mTLS 1.3 ciphertext.",
      fields: [
        { name: "type", type: 'Literal["RELAY_INVITE"]' },
        { name: "session_id", type: "str" },
        { name: "from_fingerprint", type: "str" },
        { name: "token", type: "str (30s single-use Bearer)" }
      ],
      json: {
        type: "RELAY_INVITE",
        session_id: "rel_9f3c2a8b14e0",
        from_fingerprint: "a19f4c82d0b3e7149a6c5d128f4e3b09c7d8a6f5e4d3c2b1a0987654321f8e04",
        token: "tok_resp_3kP8nV5qR2..."
      },
      keywords: "relay_invite 1003 1008 1009 binary 64kib 65536 bearer mtls pubsub a2b b2a"
    },
    {
      id: "UDP BVST Packet",
      category: "udp",
      categoryLabel: "UDP Binary",
      direction: "Client \u2194 UDP :3478",
      route: "UDP :3478 (Async DatagramProtocol)",
      limits: ["20B Probe", "99B IPv4 / 111B IPv6 Reply", "Ed25519 Signed"],
      description:
        "Raw binary STUN-like NAT reflection protocol. Clients send a 20-byte request starting with 0x42565354 ('BVST') and 16 random nonce bytes; the server returns the observed public IP:port, epoch timestamp, and 64-byte Ed25519 signature verified using GET /api/v1/info.",
      fields: [
        { name: "MAGIC_BYTES", type: 'b"BVST" (0x42565354, 4B)' },
        { name: "CLIENT_NONCE", type: "16B echo" },
        { name: "IP_VERSION", type: "1B uint8 (4 or 6)" },
        { name: "SIGNATURE", type: "64B Ed25519 over [0:31+L]" }
      ],
      isUdp: true,
      keywords: "udp bvst 0x42565354 stun 3478 ed25519 99 111 ipv4 ipv6 packet binary"
    }
  ];

  const UDP_SPECS = {
    ipv4: {
      totalBytes: 99,
      rows: [
        { offset: "[0:4]", len: "4 B", field: "Magic Bytes", value: '0x42565354 (b"BVST")' },
        { offset: "[4:20]", len: "16 B", field: "Client Nonce", value: "Echoed 16B probe nonce" },
        { offset: "[20]", len: "1 B", field: "Address Family", value: "uint8 = 4 (IPv4)" },
        { offset: "[21:25]", len: "4 B", field: "Observed IP", value: "ip.packed (198.51.100.42 -> C6 33 64 2A)" },
        { offset: "[25:27]", len: "2 B", field: "Observed Port", value: "uint16 !H (51820 -> CA 6C)" },
        { offset: "[27:35]", len: "8 B", field: "Server Epoch", value: "uint64 !Q big-endian seconds" },
        { offset: "[35:99]", len: "64 B", field: "Ed25519 Signature", value: "Signs bytes [0:35] with UDP signing key" }
      ],
      hex: [
        "# Request Probe (20 bytes -> udp://control:3478)",
        "42 56 53 54   a1 b2 c3 d4 e5 f6 07 18 29 3a 4b 5c 6d 7e 8f 90",
        "",
        "# Signed IPv4 Response (99 bytes)",
        "0000: 42 56 53 54 a1 b2 c3 d4 e5 f6 07 18 29 3a 4b 5c  |BVST........):K\\|",
        "0010: 6d 7e 8f 90 04 c6 33 64 2a ca 6c 00 00 00 00 6b  |m~....3d*.l....k|",
        "0020: 04 91 c0 [..64-byte Ed25519 signature over 0..34..] |...<Ed25519_Sig>|"
      ].join("\n")
    },
    ipv6: {
      totalBytes: 111,
      rows: [
        { offset: "[0:4]", len: "4 B", field: "Magic Bytes", value: '0x42565354 (b"BVST")' },
        { offset: "[4:20]", len: "16 B", field: "Client Nonce", value: "Echoed 16B probe nonce" },
        { offset: "[20]", len: "1 B", field: "Address Family", value: "uint8 = 6 (IPv6)" },
        { offset: "[21:37]", len: "16 B", field: "Observed IP", value: "ip.packed (2001:db8::42, 16 bytes)" },
        { offset: "[37:39]", len: "2 B", field: "Observed Port", value: "uint16 !H (51820 -> CA 6C)" },
        { offset: "[39:47]", len: "8 B", field: "Server Epoch", value: "uint64 !Q big-endian seconds" },
        { offset: "[47:111]", len: "64 B", field: "Ed25519 Signature", value: "Signs bytes [0:47] with UDP signing key" }
      ],
      hex: [
        "# Request Probe (20 bytes -> udp://[::]:3478)",
        "42 56 53 54   a1 b2 c3 d4 e5 f6 07 18 29 3a 4b 5c 6d 7e 8f 90",
        "",
        "# Signed IPv6 Response (111 bytes)",
        "0000: 42 56 53 54 a1 b2 c3 d4 e5 f6 07 18 29 3a 4b 5c  |BVST........):K\\|",
        "0010: 6d 7e 8f 90 06 20 01 0d b8 00 00 00 00 00 00 00  |m~... ..........|",
        "0020: 00 00 00 00 42 ca 6c 00 00 00 00 6b 04 91 c0 [..] |....B.l....k....|"
      ].join("\n")
    }
  };

  const searchInput = document.getElementById("protocol-search");
  const filterChips = Array.from(document.querySelectorAll(".filter-chip"));
  const protocolList = document.getElementById("protocol-list");
  const protocolEmpty = document.getElementById("protocol-empty");
  const resetProtoBtn = document.getElementById("reset-proto-btn");
  const inspector = document.getElementById("protocol-inspector");

  let selectedCategory = "all";
  let searchQuery = "";
  let selectedProtocolId = "HELLO";
  let udpFamily = "ipv4";

  function getFilteredItems() {
    const q = searchQuery.trim().toLowerCase();
    return PROTOCOL_ITEMS.filter((item) => {
      if (selectedCategory !== "all" && item.category !== selectedCategory) {
        return false;
      }
      if (!q) return true;
      const haystack = [
        item.id,
        item.categoryLabel,
        item.direction,
        item.route,
        item.description,
        item.limits.join(" "),
        item.fields.map((f) => `${f.name} ${f.type}`).join(" "),
        item.keywords
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(q);
    });
  }

  function el(tag, className, textContent) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (textContent !== undefined) node.textContent = textContent;
    return node;
  }

  function renderProtocolList() {
    if (!protocolList || !protocolEmpty) return;
    const items = getFilteredItems();
    protocolList.innerHTML = "";

    if (items.length === 0) {
      protocolEmpty.hidden = false;
      renderEmptyInspector();
      return;
    }

    protocolEmpty.hidden = true;
    if (!items.some((item) => item.id === selectedProtocolId)) {
      selectedProtocolId = items[0].id;
    }

    items.forEach((item) => {
      const btn = el("button", "proto-pill-btn");
      btn.type = "button";
      if (item.id === selectedProtocolId) btn.classList.add("is-active");
      btn.setAttribute("aria-pressed", String(item.id === selectedProtocolId));

      const nameSpan = el("span", "", item.id);
      const tagSpan = el("span", "proto-cat-tag", item.categoryLabel);
      btn.appendChild(nameSpan);
      btn.appendChild(tagSpan);

      btn.addEventListener("click", () => {
        selectedProtocolId = item.id;
        renderProtocolList();
        renderInspector();
      });

      protocolList.appendChild(btn);
    });

    renderInspector();
  }

  function renderEmptyInspector() {
    if (!inspector) return;
    inspector.innerHTML = "";
    const msg = el("p", "inspector-desc", "No wire protocol message matches your current filter.");
    inspector.appendChild(msg);
  }

  function renderInspector() {
    if (!inspector) return;
    const item = PROTOCOL_ITEMS.find((entry) => entry.id === selectedProtocolId);
    if (!item) return;

    inspector.innerHTML = "";

    // Header
    const header = el("div", "inspector-header");
    const titleRow = el("div", "inspector-title-row");
    const h3 = el("h3", "mono", item.id);
    const dirBadge = el("span", "status-badge badge-indigo", item.direction);
    const routeBadge = el("span", "status-badge badge-cyan mono", item.route);
    titleRow.appendChild(h3);
    titleRow.appendChild(dirBadge);
    titleRow.appendChild(routeBadge);

    const limitsWrap = el("div", "inspector-badges");
    item.limits.forEach((lim) => {
      limitsWrap.appendChild(el("span", "fact-chip mono", lim));
    });

    header.appendChild(titleRow);
    header.appendChild(limitsWrap);
    inspector.appendChild(header);

    // Description
    inspector.appendChild(el("p", "inspector-desc", item.description));

    // Schema fields
    const fieldsGrid = el("div", "schema-fields-grid");
    item.fields.forEach((field) => {
      const chip = el("div", "schema-field-chip mono");
      const code = el("code", "", field.name);
      const span = el("span", "", ": " + field.type);
      chip.appendChild(code);
      chip.appendChild(span);
      fieldsGrid.appendChild(chip);
    });
    inspector.appendChild(fieldsGrid);

    if (item.isUdp) {
      const spec = UDP_SPECS[udpFamily] || UDP_SPECS.ipv4;

      const tableWrap = el("div", "udp-offset-grid");
      const scroll = el("div", "table-scroll");
      const table = el("table", "udp-offset-table mono");
      const thead = el("thead");
      const headTr = el("tr");
      ["Byte Offset", "Size", "Field", "Encoding / Value"].forEach((col) => {
        headTr.appendChild(el("th", "", col));
      });
      thead.appendChild(headTr);
      table.appendChild(thead);

      const tbody = el("tbody");
      spec.rows.forEach((r) => {
        const tr = el("tr");
        tr.appendChild(el("td", "", r.offset));
        tr.appendChild(el("td", "", r.len));
        tr.appendChild(el("td", "", r.field));
        tr.appendChild(el("td", "", r.value));
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      scroll.appendChild(table);
      tableWrap.appendChild(scroll);
      inspector.appendChild(tableWrap);

      const codeShell = el("div", "inspector-code-shell");
      const codeBar = el("div", "inspector-code-bar");

      const famSwitch = el("div", "udp-family-switch");
      const ipv4Btn = el("button", "udp-fam-btn" + (udpFamily === "ipv4" ? " is-active" : ""), "IPv4 (99 B)");
      ipv4Btn.type = "button";
      ipv4Btn.addEventListener("click", () => {
        udpFamily = "ipv4";
        renderInspector();
      });
      const ipv6Btn = el("button", "udp-fam-btn" + (udpFamily === "ipv6" ? " is-active" : ""), "IPv6 (111 B)");
      ipv6Btn.type = "button";
      ipv6Btn.addEventListener("click", () => {
        udpFamily = "ipv6";
        renderInspector();
      });
      famSwitch.appendChild(ipv4Btn);
      famSwitch.appendChild(ipv6Btn);

      const copyBtn = buildCopyButton(() => spec.hex);
      codeBar.appendChild(famSwitch);
      codeBar.appendChild(copyBtn);

      const pre = el("pre", "step-json-pre mono");
      pre.appendChild(el("code", "", spec.hex));

      codeShell.appendChild(codeBar);
      codeShell.appendChild(pre);
      inspector.appendChild(codeShell);
    } else {
      const jsonStr = JSON.stringify(item.json, null, 2);
      const codeShell = el("div", "inspector-code-shell");
      const codeBar = el("div", "inspector-code-bar");
      codeBar.appendChild(el("span", "code-route mono", "schemas.py \u2022 JSON Wire Envelope"));
      codeBar.appendChild(buildCopyButton(() => jsonStr));

      const pre = el("pre", "step-json-pre mono");
      pre.appendChild(el("code", "", jsonStr));

      codeShell.appendChild(codeBar);
      codeShell.appendChild(pre);
      inspector.appendChild(codeShell);
    }
  }

  function buildCopyButton(getText) {
    const btn = el("button", "btn-copy");
    btn.type = "button";
    btn.id = "copy-proto-btn";
    btn.setAttribute("aria-label", "Copy active wire sample");
    btn.innerHTML =
      '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">' +
      '<rect x="9" y="9" width="11" height="11" rx="2" stroke="currentColor" stroke-width="2" />' +
      '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" stroke="currentColor" stroke-width="2" />' +
      "</svg>";
    const label = el("span", "", "Copy");
    btn.appendChild(label);
    btn.addEventListener("click", () => {
      copyTextWithFeedback(getText(), btn, label);
    });
    return btn;
  }

  if (searchInput) {
    searchInput.addEventListener("input", () => {
      searchQuery = searchInput.value;
      renderProtocolList();
    });
  }

  filterChips.forEach((chip) => {
    chip.addEventListener("click", () => {
      selectedCategory = chip.dataset.category || "all";
      filterChips.forEach((btn) => {
        const active = btn === chip;
        btn.classList.toggle("is-active", active);
        btn.setAttribute("aria-selected", String(active));
      });
      renderProtocolList();
    });
  });

  if (resetProtoBtn) {
    resetProtoBtn.addEventListener("click", () => {
      searchQuery = "";
      selectedCategory = "all";
      if (searchInput) searchInput.value = "";
      filterChips.forEach((btn) => {
        const active = btn.dataset.category === "all";
        btn.classList.toggle("is-active", active);
        btn.setAttribute("aria-selected", String(active));
      });
      renderProtocolList();
    });
  }

  renderProtocolList();

  // 5. Collapsible Full Benchmark Drawer
  const toggleBenchBtn = document.getElementById("toggle-bench-btn");
  const toggleBenchLabel = document.getElementById("toggle-bench-label");
  const benchDrawer = document.getElementById("bench-drawer");

  if (toggleBenchBtn && benchDrawer) {
    toggleBenchBtn.addEventListener("click", () => {
      const expanded = toggleBenchBtn.getAttribute("aria-expanded") === "true";
      const next = !expanded;
      toggleBenchBtn.setAttribute("aria-expanded", String(next));
      benchDrawer.hidden = !next;
      if (toggleBenchLabel) {
        toggleBenchLabel.textContent = next
          ? "Hide Full Benchmark Table"
          : "View Full Benchmark Table (benchmarks/bench_control.py)";
      }
    });
  }

  // 6. Tabbed Deploy Workbench & Copy
  const deployTabs = Array.from(document.querySelectorAll("[data-deploy-tab]"));
  const deployPanels = Array.from(document.querySelectorAll("[data-deploy-panel]"));
  const copyDeployBtn = document.getElementById("copy-deploy-btn");
  const copyDeployLabel = document.getElementById("copy-deploy-label");

  deployTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const target = tab.dataset.deployTab;
      deployTabs.forEach((btn) => {
        const active = btn === tab;
        btn.classList.toggle("is-active", active);
        btn.setAttribute("aria-selected", String(active));
      });
      deployPanels.forEach((panel) => {
        const active = panel.dataset.deployPanel === target;
        panel.hidden = !active;
        panel.classList.toggle("is-active", active);
      });
    });
  });

  if (copyDeployBtn) {
    copyDeployBtn.addEventListener("click", () => {
      const activePanel = deployPanels.find((panel) => !panel.hidden);
      const text = activePanel ? activePanel.innerText.trim() : "";
      copyTextWithFeedback(text, copyDeployBtn, copyDeployLabel);
    });
  }

  // 7. Gentle Scroll Reveal
  const revealEls = Array.from(document.querySelectorAll(".reveal-on-scroll"));
  if ("IntersectionObserver" in window && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    const observer = new IntersectionObserver(
      (entries, obs) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            obs.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.08, rootMargin: "0px 0px -30px 0px" }
    );
    revealEls.forEach((elItem) => observer.observe(elItem));
  } else {
    revealEls.forEach((elItem) => elItem.classList.add("is-visible"));
  }
})();
