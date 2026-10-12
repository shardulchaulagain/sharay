"""Versioned API input contracts."""

from pydantic import BaseModel, ConfigDict, Field

from packages.security_policies import ScopePolicy


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Login(Input):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=1, max_length=256)


class MemberInput(Input):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=12, max_length=256)
    role: str


class ProjectInput(Input):
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=4000)


class ProjectUpdate(Input):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=4000)
    archived: bool | None = None


class TargetInput(Input):
    url: str = Field(min_length=1, max_length=2048)
    scope: ScopePolicy


class ApprovalInput(Input):
    acknowledgement: str


class AssessmentInput(Input):
    target_id: str
    idempotency_key: str = Field(min_length=8, max_length=100)
    retest_of: str | None = None


class FindingUpdate(Input):
    status: str
