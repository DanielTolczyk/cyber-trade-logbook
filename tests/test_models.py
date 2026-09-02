"""Tests for Canonical Logbook Models."""

from datetime import date, datetime, timezone
from cyber_trade_logbook.models import (
    LogbookEntry,
    PractitionerProfile,
    SupervisorProfile,
    RuntimeExecution,
    VerificationArtifact,
    DigitalAttestation,
    PhysicalAttestation,
)


def test_valid_digital_logbook_entry():
    entry = LogbookEntry(
        log_id="urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
        entry_modality="digital",
        practitioner=PractitionerProfile(
            trade_id="CTP-APP-2026-0884",
            name="Angela Moss",
            tier="Tier 2 Apprentice"
        ),
        supervisor=SupervisorProfile(
            trade_id="CTP-JRN-2024-0192",
            license_status="Active",
            supervision_ratio_compliant=True
        ),
        runtime_execution=RuntimeExecution(
            date=date(2026, 8, 25),
            hours_logged=4.5,
            core_domain="D2_SYSTEM_HYGIENE",
            sub_domain="CI_CD_PIPELINE_HARDENING",
            environment_type="Enterprise_Production"
        ),
        verification_artifacts=[
            VerificationArtifact(
                artifact_type="git_commit_hash",
                artifact_reference="sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                sanitized_summary="Enforced Cosign signature validation."
            )
        ],
        attestation=DigitalAttestation(
            supervisor_signature="SIG_MOCK_12345",
            signed_timestamp=datetime.now(timezone.utc)
        )
    )

    assert entry.runtime_execution.hours_logged == 4.5
    assert entry.runtime_execution.core_domain == "D2_SYSTEM_HYGIENE"
    assert entry.practitioner.trade_id == "CTP-APP-2026-0884"


def test_valid_physical_logbook_entry():
    entry = LogbookEntry(
        log_id="urn:uuid:12345678-1234-5678-1234-567812345678",
        entry_modality="physical_bound",
        practitioner=PractitionerProfile(
            trade_id="CTP-APP-2026-0884",
            name="Angela Moss",
            tier="Tier 1 Apprentice"
        ),
        runtime_execution=RuntimeExecution(
            date=date(2026, 8, 25),
            hours_logged=6.0,
            core_domain="D1_PERIMETER_CLOUD",
            environment_type="Classified_SCIF_Enclave"
        ),
        physical_attestation=PhysicalAttestation(
            book_serial_number="JATC-LOG-2026-00441",
            page_number=42,
            line_number=3,
            supervisor_name="Marcus Vance",
            supervisor_license_id="CTP-JRN-2024-0192",
            physical_signature_recorded=True,
            physical_stamp_present=True
        )
    )

    assert entry.entry_modality == "physical_bound"
    assert entry.physical_attestation.book_serial_number == "JATC-LOG-2026-00441"
    assert entry.physical_attestation.page_number == 42
