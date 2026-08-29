"""Canonical Pydantic models conforming to The Cybersecurity Trade Project specifications."""

from datetime import date, datetime
from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field


class PractitionerProfile(BaseModel):
    trade_id: str = Field(..., description="Practitioner Trade Registration ID (e.g. CTP-APP-2026-0884)")
    name: str = Field(..., description="Full Legal Name")
    tier: str = Field("Tier 1 Apprentice", description="Current Apprentice Tier or Licensure Standing")
    public_key_fingerprint: Optional[str] = Field(None, description="SHA-256 fingerprint of practitioner Trade Public Key")


class SupervisorProfile(BaseModel):
    trade_id: str = Field(..., description="Supervisor License ID (e.g. CTP-JRN-2024-0192)")
    license_status: Literal["Active", "Suspended", "Lapsed"] = "Active"
    supervision_ratio_compliant: bool = True
    public_key_fingerprint: Optional[str] = Field(None, description="SHA-256 fingerprint of supervisor Trade Public Key")


class RuntimeExecution(BaseModel):
    date: date
    hours_logged: float = Field(..., gt=0, le=24.0)
    core_domain: Literal[
        "D1_PERIMETER_CLOUD",
        "D2_SYSTEM_HYGIENE",
        "D3_IDENTITY_ACCESS",
        "D4_VULN_MANAGEMENT",
        "D5_DEFENSIVE_GRC"
    ]
    sub_domain: Optional[str] = None
    environment_type: Literal[
        "Enterprise_Production",
        "Cloud_Infrastructure",
        "Classified_SCIF_Enclave",
        "Range_Lab"
    ] = "Enterprise_Production"


class CompetencyMilestone(BaseModel):
    code: str
    description: str


class VerificationArtifact(BaseModel):
    artifact_type: Literal[
        "git_commit_hash",
        "change_ticket_id",
        "incident_record_id",
        "pipeline_run_hash",
        "rule_hash",
        "model_eval_hash",
        "guardrail_policy_hash",
        "telemetry_export_token"
    ]
    artifact_reference: str
    sanitized_summary: str


class DigitalAttestation(BaseModel):
    supervisor_signature: str
    signed_timestamp: datetime
    attestation_statement: str = "I verify that the above runtime hours reflect authentic, supervised operational execution conforming to trade quality rubrics."
    supervisor_public_key: Optional[str] = None


class PhysicalAttestation(BaseModel):
    book_serial_number: str
    page_number: int = Field(..., ge=1)
    line_number: int = Field(..., ge=1, le=50)
    supervisor_name: str
    supervisor_license_id: str
    physical_signature_recorded: bool = True
    physical_stamp_present: bool = True
    scanned_page_sha256: Optional[str] = None
    jatc_audit_status: Literal["Pending_Quarterly_Review", "Audited_Approved", "Rejected"] = "Pending_Quarterly_Review"


class InvalidationBlock(BaseModel):
    """Cryptographic revocation block signed by a supervisor to invalidate a prior mistaken entry without breaking hash chain."""
    invalidation_id: str
    target_entry_id: str = Field(..., description="UUID / Log ID of the entry being invalidated")
    reason_category: Literal[
        "ADMINISTRATIVE_SIGNING_ERROR",
        "DUPLICATE_SHIFT_LOGGED",
        "TASK_DOMAIN_MISCLASSIFICATION",
        "DISPUTED_HOURS_RECONCILIATION"
    ]
    sanitized_justification: str
    hours_reversed: float
    domain_reversed: str
    supervisor_trade_id: str
    supervisor_signature_b64: str
    invalidation_timestamp: datetime


class LogbookEntry(BaseModel):
    schema_uri: str = Field(
        default="https://cybertrade.org/schemas/v1/logbook-entry.json",
        alias="$schema"
    )
    log_id: str
    version: str = "1.1.0"
    entry_modality: Literal["digital", "physical_bound"] = "digital"
    entry_type: Literal["operational_runtime", "invalidation_tombstone"] = "operational_runtime"
    is_invalidated: bool = False
    invalidation: Optional[InvalidationBlock] = None
    prev_entry_hash: str = Field(
        default="0000000000000000000000000000000000000000000000000000000000000000",
        description="SHA-256 hash of previous sequential entry, enforcing tamper-proof hash chain"
    )
    entry_hash: Optional[str] = Field(
        default=None,
        description="SHA-256 hash of this entry payload binding practitioner identity, hours, domain, and artifact"
    )
    practitioner: PractitionerProfile
    supervisor: Optional[SupervisorProfile] = None
    runtime_execution: RuntimeExecution
    competency_milestone: Optional[CompetencyMilestone] = None
    verification_artifacts: List[VerificationArtifact] = Field(default_factory=list)
    attestation: Optional[DigitalAttestation] = None
    physical_attestation: Optional[PhysicalAttestation] = None


class UnderwriterComplianceSummary(BaseModel):
    active_master_of_record: bool
    mor_trade_id_hash: str
    supervisory_ratio_compliance_score: float = Field(..., ge=0.0, le=1.0)
    total_verified_ojt_hours: float
    specialty_endorsements_active: List[str]
    unresolved_safety_non_concurrences: int = 0


class ActuarialAttestationFeed(BaseModel):
    schema_uri: str = Field(
        default="https://cybertrade.org/schemas/v1/underwriter-attestation.json",
        alias="$schema"
    )
    attestation_id: str
    reporting_period: Dict[str, Any]
    organization_identifier: str
    compliance_summary: UnderwriterComplianceSummary
    clearinghouse_signature: Dict[str, Any]


class EncryptedSubmissionBundle(BaseModel):
    """Encrypted envelope for submitting personal logbook ledgers to JATC / Clearinghouse."""
    bundle_id: str
    created_at: datetime
    practitioner_trade_id: str
    practitioner_pubkey: str
    recipient_clearinghouse_id: str
    chain_head_hash: str
    total_entries_count: int
    encrypted_payload_b64: str
    nonce_b64: str
    practitioner_submission_signature_b64: str


class CertifiedTradeCredential(BaseModel):
    """Board-signed cryptographic credential binding a practitioner's public key to their legal standing and tier."""
    credential_id: str
    trade_id: str = Field(..., description="Trade License or Registration ID (e.g. CTP-JRN-2024-0192)")
    legal_name: str
    certified_role: Literal["Registered Apprentice", "Licensed Journeyman", "Master Practitioner", "JATC Training Director"]
    public_key_pem: str
    issued_timestamp: datetime
    expires_timestamp: datetime
    board_root_signature_b64: str

class JATCPhysicalAuditSeal(BaseModel):
    """Accreditation Seal issued by a JATC Training Director upon in-person physical logbook audit."""
    accreditation_type: Literal["JATC_PHYSICAL_BOOK_AUDIT_SEAL"] = "JATC_PHYSICAL_BOOK_AUDIT_SEAL"
    audit_seal_id: str
    practitioner_trade_id: str
    book_serial_number: str
    start_page: int = Field(..., ge=1)
    end_page: int = Field(..., ge=1)
    total_verified_hours: float = Field(..., gt=0)
    domain_breakdown: Dict[str, float]
    supervisors_verified: List[str]
    examiner_name: str
    examiner_trade_id: str = Field(..., description="Examiner JATC Training Director or Master ID")
    regional_local: str
    audit_timestamp: datetime
    examiner_signature_b64: str



