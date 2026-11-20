"""Configuration management using Pydantic Settings."""

from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings for blindvault-control."""

    model_config = SettingsConfigDict(
        env_prefix="BLINDVAULT_",
        case_sensitive=False,
        env_file=".env",
        extra="ignore",
    )

    # Environment
    ENVIRONMENT: Literal["development", "test", "production"] = "development"

    # Server binding
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Origin validation for WebSockets (empty list rejects browser origins; ["*"] allows all)
    ALLOWED_ORIGINS: list[str] = Field(default_factory=list)

    # UDP STUN-like Endpoint Reflector (Ed25519 private key: PEM, 64-hex seed, or base64 raw 32B)
    UDP_HOST: str = "0.0.0.0"
    UDP_PORT: int = 3478
    UDP_SIGNING_PRIVATE_KEY: str = ""

    # Redis backend
    REDIS_URL: str = "redis://localhost:6379/0"

    # Rate limits (events per minute)
    RATE_LIMIT_HANDSHAKE_PER_MIN: int = 10
    RATE_LIMIT_INVITE_PER_MIN: int = 10
    RATE_LIMIT_CLAIM_PER_MIN: int = 10
    RATE_LIMIT_RELAY_PER_MIN: int = 5

    # Relay boundaries
    RELAY_MAX_SESSION_SECONDS: int = 900  # 15 minutes max
    RELAY_IDLE_TIMEOUT_SECONDS: int = 30  # 30 seconds idle timeout
    RELAY_MAX_FRAME_BYTES: int = 65536  # 64 KiB max frame size
    RELAY_CHUNK_BYTES: int = 65536  # 64 KiB chunk size for streaming
    CONTROL_MAX_FRAME_BYTES: int = 8192  # 8 KiB max control frame

    # TTLs (seconds)
    PRESENCE_TTL_SECONDS: int = 60
    CHALLENGE_TTL_SECONDS: int = 30
    INVITE_TTL_SECONDS: int = 300
    RELAY_TOKEN_TTL_SECONDS: int = 30
    HEARTBEAT_INTERVAL_SECONDS: int = 20

    # Logging & privacy
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    SCRUB_IPS_IN_LOGS: bool = True


settings = Settings()
