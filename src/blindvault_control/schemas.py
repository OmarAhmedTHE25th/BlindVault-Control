"""Pydantic v2 schemas for WebSocket signaling and control protocol."""

from typing import Any, Literal

from pydantic import BaseModel, Field


# Base Protocol Message
class BaseMessage(BaseModel):
    """Base class for all JSON wire protocol messages."""

    type: str


# ---------- Client -> Server Messages ----------


class HelloMessage(BaseMessage):
    """Initial client hello carrying EC P-256 public key material."""

    type: Literal["HELLO"] = "HELLO"
    public_key: str
    observed_endpoint: str | None = None


class AuthMessage(BaseMessage):
    """Challenge response carrying ECDSA signature over the server-issued nonce."""

    type: Literal["AUTH"] = "AUTH"
    signature: str


class PingMessage(BaseMessage):
    """Heartbeat keepalive ping."""

    type: Literal["PING"] = "PING"


class CreateInviteMessage(BaseMessage):
    """Request an ephemeral Crockford Base32 invite pairing code."""

    type: Literal["CREATE_INVITE"] = "CREATE_INVITE"
    endpoints: list[dict[str, Any]] = Field(default_factory=list)


class ClaimInviteMessage(BaseMessage):
    """Claim an ephemeral pairing invite code."""

    type: Literal["CLAIM_INVITE"] = "CLAIM_INVITE"
    code: str


class SignalOfferMessage(BaseMessage):
    """Forward ICE / direct candidate offer to a paired peer."""

    type: Literal["SIGNAL_OFFER"] = "SIGNAL_OFFER"
    target_fingerprint: str
    session_id: str
    candidate: dict[str, Any] = Field(default_factory=dict)


class SignalAnswerMessage(BaseMessage):
    """Forward ICE / direct candidate answer to a paired peer."""

    type: Literal["SIGNAL_ANSWER"] = "SIGNAL_ANSWER"
    target_fingerprint: str
    session_id: str
    candidate: dict[str, Any] = Field(default_factory=dict)


class HolePunchSyncMessage(BaseMessage):
    """Synchronize UDP punch timing between paired peers."""

    type: Literal["HOLE_PUNCH_SYNC"] = "HOLE_PUNCH_SYNC"
    target_fingerprint: str
    stage: str
    timestamp: float | None = None


class CreateRelayMessage(BaseMessage):
    """Request an encrypted fallback relay session when direct traversal fails."""

    type: Literal["CREATE_RELAY"] = "CREATE_RELAY"
    target_fingerprint: str


# ---------- Server -> Client Messages ----------


class ChallengeMessage(BaseMessage):
    """Server challenge containing cryptographic nonce and computed peer fingerprint."""

    type: Literal["CHALLENGE"] = "CHALLENGE"
    nonce: str
    fingerprint: str


class AuthOkMessage(BaseMessage):
    """Successful authentication confirmation."""

    type: Literal["AUTH_OK"] = "AUTH_OK"
    fingerprint: str


class AuthFailedMessage(BaseMessage):
    """Authentication rejection notice."""

    type: Literal["AUTH_FAILED"] = "AUTH_FAILED"
    reason: str


class PongMessage(BaseMessage):
    """Heartbeat keepalive pong."""

    type: Literal["PONG"] = "PONG"


class InviteCreatedMessage(BaseMessage):
    """Generated ephemeral pairing invite code."""

    type: Literal["INVITE_CREATED"] = "INVITE_CREATED"
    code: str
    ttl: int


class PeerMatchedMessage(BaseMessage):
    """Mutual peer connection parameters delivered upon pairing claim."""

    type: Literal["PEER_MATCHED"] = "PEER_MATCHED"
    peer_fingerprint: str
    endpoints: list[dict[str, Any]]
    role: Literal["creator", "claimer"]


class RelayCreatedMessage(BaseMessage):
    """Relay session rendezvous details for the initiator."""

    type: Literal["RELAY_CREATED"] = "RELAY_CREATED"
    session_id: str
    token: str


class RelayInviteMessage(BaseMessage):
    """Relay session rendezvous invitation delivered to the target peer."""

    type: Literal["RELAY_INVITE"] = "RELAY_INVITE"
    session_id: str
    from_fingerprint: str
    token: str


class ErrorMessage(BaseMessage):
    """Control protocol error notification."""

    type: Literal["ERROR"] = "ERROR"
    code: str
    message: str


# Type alias for parsed incoming client messages
ClientMessage = (
    HelloMessage
    | AuthMessage
    | PingMessage
    | CreateInviteMessage
    | ClaimInviteMessage
    | SignalOfferMessage
    | SignalAnswerMessage
    | HolePunchSyncMessage
    | CreateRelayMessage
)
