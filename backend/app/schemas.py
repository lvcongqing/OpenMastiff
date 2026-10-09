from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, HttpUrl, validator
from typing_extensions import Literal


class RequestStatus(str, Enum):
    Draft = "Draft"
    Submitted = "Submitted"
    Scanning = "Scanning"
    Reviewing = "Reviewing"
    LegalReviewing = "LegalReviewing"
    Blocked = "Blocked"
    Approved = "Approved"
    ConditionalApproved = "ConditionalApproved"
    Remediating = "Remediating"
    ReReview = "ReReview"
    Rejected = "Rejected"
    Waived = "Waived"


class GateStatus(str, Enum):
    Pass = "Pass"
    Fail = "Fail"
    PendingLegal = "PendingLegal"
    Unknown = "Unknown"


class SourceType(str, Enum):
    upload = "upload"
    git = "git"


class ScanScopeIn(BaseModel):
    mode: Literal["auto", "include_paths"] = "auto"
    include_paths: list = Field(default_factory=list)


class CreateRequestIn(BaseModel):
    project: str
    environment: str
    purpose: str
    business_criticality: Literal["low", "medium", "high", "critical"]
    exposure: Literal["internal", "public"]
    rollback_plan: str
    required_review_roles: list = Field(default_factory=list)
    title: Optional[str] = None
    owner: Optional[str] = None
    scan_scope: Optional[ScanScopeIn] = None


class BatchRequestItemIn(BaseModel):
    project: str
    purpose: str
    repo_url: str
    ref: str = "main"
    environment: str = "dev"
    exposure: Literal["internal", "public"] = "internal"
    business_criticality: Literal["low", "medium", "high", "critical"] = "low"
    rollback_plan: str = "version_downgrade"
    title: Optional[str] = None
    owner: Optional[str] = None
    credential_id: Optional[str] = None
    include_paths: list = Field(default_factory=list)
    extra_review_roles: list = Field(default_factory=list)
    row: Optional[int] = None


class BatchCreateIn(BaseModel):
    items: list
    submit: bool = True


class UpdateRequestIn(BaseModel):
    """Partial update. 扫描中不可改；角色与扫描范围仅草稿/复审可改。"""

    project: Optional[str] = None
    environment: Optional[str] = None
    purpose: Optional[str] = None
    business_criticality: Optional[Literal["low", "medium", "high", "critical"]] = None
    exposure: Optional[Literal["internal", "public"]] = None
    rollback_plan: Optional[str] = None
    title: Optional[str] = None
    owner: Optional[str] = None
    scan_scope: Optional[ScanScopeIn] = None
    required_review_roles: Optional[list] = None


class RequestOut(BaseModel):
    request_id: str
    status: RequestStatus
    gate_status: GateStatus
    project: str
    title: Optional[str] = None
    owner: Optional[str] = None
    created_by: Optional[str] = None
    risk_level: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class SetGitSourceIn(BaseModel):
    repo_url: HttpUrl
    ref: str = Field(min_length=1)
    credential_id: Optional[str] = None


class SubmitOut(BaseModel):
    request_id: str
    status: RequestStatus
    scan_run_id: str


class LegalReviewStatus(str, Enum):
    Pending = "Pending"
    Allowed = "Allowed"
    Denied = "Denied"


class CreateLegalReviewOut(BaseModel):
    legal_review_id: str
    request_id: str
    status: LegalReviewStatus
    created_at: datetime


class LegalDecisionIn(BaseModel):
    decision: Literal["Allowed", "Denied"]
    rationale: str = Field(min_length=1)


class DecisionType(str, Enum):
    Approved = "Approved"
    ConditionalApproved = "ConditionalApproved"
    Rejected = "Rejected"
    Waived = "Waived"


class DecisionIn(BaseModel):
    decision: DecisionType
    comment: Optional[str] = None
    review_role: Optional[str] = None

    # Waiver required
    risk_acceptor: Optional[str] = None
    compensating_controls: Optional[str] = None
    expires_at: Optional[datetime] = None

    @validator("expires_at", pre=True)
    def _parse_expires_at(cls, v):
        if v in (None, ""):
            return None
        if isinstance(v, datetime):
            return v
        s = str(v).strip()
        if s.endswith("Z"):
            s = s[:-1]
        if len(s) > 10 and "+" in s[10:]:
            s = s.split("+", 1)[0]
        s = s.replace(" ", "T")
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                continue
        raise ValueError("expires_at 格式无效，请使用日期时间")


class FindingDispositionIn(BaseModel):
    disposition: Literal["open", "false_positive", "accepted_risk", "confirmed"]
    fingerprints: list = Field(default_factory=list)
    rule_id: Optional[str] = None
    category: Optional[str] = None
    reason: Optional[str] = None


def new_id() -> str:
    return uuid4().hex


def now_utc() -> datetime:
    return datetime.utcnow()

