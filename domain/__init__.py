"""Domain enums and shared types for the product control plane."""

from __future__ import annotations

from enum import Enum


class OrgRole(str, Enum):
    OWNER = "owner"
    OPERATOR = "operator"
    VIEWER = "viewer"


class OrgStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DELETED = "deleted"


class ProjectStatus(str, Enum):
    ACTIVE = "active"
    ARCHIVED = "archived"


class AgentStatus(str, Enum):
    DRAFT = "draft"
    REGISTERED = "registered"
    DEPRECATED = "deprecated"


class ScenarioStatus(str, Enum):
    DRAFT = "draft"
    PUBLISHED = "published"
    RETIRED = "retired"


class RunStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCEL_REQUESTED = "cancel_requested"
    CANCELLED = "cancelled"


class FindingStatus(str, Enum):
    OPEN = "open"
    ASSIGNED = "assigned"
    SUPPRESSED = "suppressed"
    ACCEPTED = "accepted"
    REMEDIATED = "remediated"
    VERIFIED = "verified"


class EvidenceStatus(str, Enum):
    PENDING = "pending"
    SEALED = "sealed"
    EXPIRED = "expired"
    PURGED = "purged"


class GateResult(str, Enum):
    PASS = "pass"
    FAIL = "fail"


class EventType(str, Enum):
    MODEL_REQUEST = "model.request"
    MODEL_RESPONSE = "model.response"
    AGENT_HANDOFF = "agent.handoff"
    TOOL_DISCOVERY = "tool.discovery"
    TOOL_CALL = "tool.call"
    TOOL_RESULT = "tool.result"
    MEMORY_OP = "memory.op"
    RETRIEVAL_OP = "retrieval.op"
    POLICY_DECISION = "policy.decision"
    APPROVAL_DECISION = "approval.decision"
    COST_TICK = "cost.tick"
    CANCEL_SIGNAL = "cancel.signal"
    SCOPE_CHANGE = "scope.change"
