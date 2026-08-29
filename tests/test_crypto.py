"""Tests for Trade Cryptographic Primitives, Hash Chains, and Anti-Cloning."""

from datetime import date, datetime, timezone
from cyber_trade_logbook.crypto import TradeKeyManager, GENESIS_HASH
from cyber_trade_logbook.models import (
    LogbookEntry,
    PractitionerProfile,
    SupervisorProfile,
    RuntimeExecution,
    VerificationArtifact,
    DigitalAttestation,
)


def make_test_entry(trade_id: str, date_val: date, hours: float, prev_hash: str) -> LogbookEntry:
    entry = LogbookEntry(
        log_id=f"urn:uuid:entry-{date_val}",
        entry_modality="digital",
        prev_entry_hash=prev_hash,
        practitioner=PractitionerProfile(
            trade_id=trade_id,
            name="Alice Defender",
            tier="Tier 2 Apprentice"
        ),
        supervisor=SupervisorProfile(
            trade_id="CTP-JRN-2024-0001",
            license_status="Active"
        ),
        runtime_execution=RuntimeExecution(
            date=date_val,
            hours_logged=hours,
            core_domain="D2_SYSTEM_HYGIENE",
            sub_domain="SIEM_RULE_AUTHORING"
        ),
        verification_artifacts=[
            VerificationArtifact(
                artifact_type="git_commit_hash",
                artifact_reference="sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
                sanitized_summary="Authored Sigma rule for suspicious Kerberos ticket requests."
            )
        ]
    )
    entry.entry_hash = TradeKeyManager.compute_entry_hash(entry, prev_hash)
    return entry


def test_sequential_hash_chain_integrity():
    p_id = "CTP-APP-2026-0884"
    e1 = make_test_entry(p_id, date(2026, 8, 1), 8.0, GENESIS_HASH)
    e2 = make_test_entry(p_id, date(2026, 8, 2), 6.0, e1.entry_hash)
    e3 = make_test_entry(p_id, date(2026, 8, 3), 7.5, e2.entry_hash)

    entries = [e1, e2, e3]
    valid, err = TradeKeyManager.verify_chain_integrity(entries)
    assert valid is True
    assert err is None


def test_tampered_entry_breaks_chain():
    p_id = "CTP-APP-2026-0884"
    e1 = make_test_entry(p_id, date(2026, 8, 1), 8.0, GENESIS_HASH)
    e2 = make_test_entry(p_id, date(2026, 8, 2), 6.0, e1.entry_hash)
    e3 = make_test_entry(p_id, date(2026, 8, 3), 7.5, e2.entry_hash)

    # Malicious attempt to change hours in e2 from 6.0 to 12.0
    e2.runtime_execution.hours_logged = 12.0

    entries = [e1, e2, e3]
    valid, err = TradeKeyManager.verify_chain_integrity(entries)
    assert valid is False
    assert "Hash mismatch at entry index 1" in err


def test_anti_cloning_identity_theft_prevention():
    """Verify that copying an entry and claiming it under another practitioner invalidates attestation."""
    sup_priv, sup_pub = TradeKeyManager.generate_keypair()
    original_id = "CTP-APP-2026-0884"
    entry = make_test_entry(original_id, date(2026, 8, 1), 8.0, GENESIS_HASH)

    # Supervisor signs entry for original practitioner
    sig = TradeKeyManager.sign_entry_attestation(sup_priv, entry, GENESIS_HASH)
    entry.attestation = DigitalAttestation(
        supervisor_signature=sig,
        signed_timestamp=datetime.now(timezone.utc)
    )

    # Verification passes for legitimate practitioner
    assert TradeKeyManager.verify_entry_attestation(sup_pub, entry, GENESIS_HASH) is True

    # Plagiarist copies entry and replaces Trade ID with their own
    entry.practitioner.trade_id = "CTP-APP-2026-9999"
    entry.practitioner.name = "Eve Copycat"

    # Signature must fail immediately because entry was signed for original_id
    assert TradeKeyManager.verify_entry_attestation(sup_pub, entry, GENESIS_HASH) is False


def test_clearinghouse_encrypted_submission_bundle():
    practitioner_priv, practitioner_pub = TradeKeyManager.generate_keypair()
    p_id = "CTP-APP-2026-0884"
    e1 = make_test_entry(p_id, date(2026, 8, 1), 8.0, GENESIS_HASH)
    e2 = make_test_entry(p_id, date(2026, 8, 2), 8.0, e1.entry_hash)
    entries = [e1, e2]

    # Create encrypted bundle
    bundle = TradeKeyManager.create_submission_bundle(
        practitioner_private_key=practitioner_priv,
        clearinghouse_id="NCTB-CLEARINGHOUSE-NATIONAL",
        entries=entries
    )

    assert bundle.practitioner_trade_id == p_id
    assert bundle.total_entries_count == 2
    assert len(bundle.encrypted_payload_b64) > 0



def test_board_credential_issuance_and_verification():
    board_priv, board_pub = TradeKeyManager.generate_keypair()
    sup_priv, sup_pub = TradeKeyManager.generate_keypair()
    
    expires = datetime(2030, 1, 1, tzinfo=timezone.utc)
    cred = TradeKeyManager.issue_board_credential(
        board_root_private_key=board_priv,
        trade_id="CTP-JRN-2024-0192",
        legal_name="Marcus Vance",
        certified_role="Licensed Journeyman",
        practitioner_public_key=sup_pub,
        expires_timestamp=expires
    )
    
    valid, err = TradeKeyManager.verify_board_credential(board_pub, cred)
    assert valid is True
    assert err is None


def test_apprentice_peer_signing_blocked():
    board_priv, board_pub = TradeKeyManager.generate_keypair()
    apprentice_priv, apprentice_pub = TradeKeyManager.generate_keypair()
    
    # Board issues credential certifying role as Registered Apprentice
    expires = datetime(2030, 1, 1, tzinfo=timezone.utc)
    apprentice_cred = TradeKeyManager.issue_board_credential(
        board_root_private_key=board_priv,
        trade_id="CTP-APP-2026-0042",
        legal_name="Bob Apprentice",
        certified_role="Registered Apprentice",
        practitioner_public_key=apprentice_pub,
        expires_timestamp=expires
    )
    
    # Apprentice tries to sign peer's entry
    target_entry = make_test_entry("CTP-APP-2026-0884", date(2026, 8, 1), 8.0, GENESIS_HASH)
    sig = TradeKeyManager.sign_entry_attestation(apprentice_priv, target_entry, GENESIS_HASH)
    target_entry.attestation = DigitalAttestation(
        supervisor_signature=sig,
        signed_timestamp=datetime.now(timezone.utc)
    )
    
    valid, err = TradeKeyManager.verify_supervisor_standing(board_pub, apprentice_cred, target_entry, GENESIS_HASH)
    assert valid is False
    assert "Only Licensed Journeymen or Masters may sign" in err


def test_self_signing_prohibition_blocked():
    board_priv, board_pub = TradeKeyManager.generate_keypair()
    journeyman_priv, journeyman_pub = TradeKeyManager.generate_keypair()
    
    # Board issues Journeyman credential
    expires = datetime(2030, 1, 1, tzinfo=timezone.utc)
    journeyman_cred = TradeKeyManager.issue_board_credential(
        board_root_private_key=board_priv,
        trade_id="CTP-JRN-2024-0192",
        legal_name="Marcus Vance",
        certified_role="Licensed Journeyman",
        practitioner_public_key=journeyman_pub,
        expires_timestamp=expires
    )
    
    # Journeyman tries to sign their own apprentice-era log entry
    own_entry = make_test_entry("CTP-JRN-2024-0192", date(2026, 8, 1), 8.0, GENESIS_HASH)
    sig = TradeKeyManager.sign_entry_attestation(journeyman_priv, own_entry, GENESIS_HASH)
    own_entry.attestation = DigitalAttestation(
        supervisor_signature=sig,
        signed_timestamp=datetime.now(timezone.utc)
    )
    
    valid, err = TradeKeyManager.verify_supervisor_standing(board_pub, journeyman_cred, own_entry, GENESIS_HASH)
    assert valid is False
    assert "Practitioner cannot sign their own operational logbook entries" in err


def test_fake_untrusted_supervisor_credential_blocked():
    board_priv, board_pub = TradeKeyManager.generate_keypair()
    fake_board_priv, _ = TradeKeyManager.generate_keypair()
    attacker_priv, attacker_pub = TradeKeyManager.generate_keypair()
    
    # Attacker issues fake credential signed with attacker's fake root
    expires = datetime(2030, 1, 1, tzinfo=timezone.utc)
    fake_cred = TradeKeyManager.issue_board_credential(
        board_root_private_key=fake_board_priv,
        trade_id="CTP-MST-9999",
        legal_name="Fake Master",
        certified_role="Master Practitioner",
        practitioner_public_key=attacker_pub,
        expires_timestamp=expires
    )
    
    target_entry = make_test_entry("CTP-APP-2026-0884", date(2026, 8, 1), 8.0, GENESIS_HASH)
    sig = TradeKeyManager.sign_entry_attestation(attacker_priv, target_entry, GENESIS_HASH)
    target_entry.attestation = DigitalAttestation(
        supervisor_signature=sig,
        signed_timestamp=datetime.now(timezone.utc)
    )
    
    valid, err = TradeKeyManager.verify_supervisor_standing(board_pub, fake_cred, target_entry, GENESIS_HASH)
    assert valid is False
    assert "Invalid Board Root signature" in err


def test_jatc_physical_audit_seal_issuance_and_verification():
    examiner_priv, examiner_pub = TradeKeyManager.generate_keypair()
    
    seal = TradeKeyManager.issue_jatc_physical_seal(
        examiner_private_key=examiner_priv,
        practitioner_trade_id="CTP-APP-2026-0884",
        book_serial_number="JATC-LOG-2026-00441",
        start_page=1,
        end_page=52,
        total_verified_hours=1400.0,
        domain_breakdown={
            "D1_PERIMETER_CLOUD": 400.0,
            "D2_SYSTEM_HYGIENE": 600.0,
            "D3_IDENTITY_ACCESS": 400.0
        },
        supervisors_verified=["CTP-JRN-2024-0192", "CTP-MST-2022-0041"],
        examiner_name="David Sterling",
        examiner_trade_id="CTP-DIR-2020-0005",
        regional_local="JATC Local 101 - Great Lakes"
    )
    
    valid, err = TradeKeyManager.verify_jatc_physical_seal(examiner_pub, seal)
    assert valid is True
    assert err is None


def test_multi_device_safe_merge_and_reconciliation():
    p_id = "CTP-APP-2026-0884"
    
    # Phone entries (Logged on mobile)
    e1 = make_test_entry(p_id, date(2026, 8, 1), 8.0, GENESIS_HASH)
    e2 = make_test_entry(p_id, date(2026, 8, 2), 6.0, e1.entry_hash)
    phone_entries = [e1, e2]
    
    # PC entries (Logged on home workstation: e1 + new e3)
    e3 = make_test_entry(p_id, date(2026, 8, 3), 7.5, e1.entry_hash)
    pc_entries = [e1, e3]
    
    # Merge Phone and PC entries
    merged, msg = TradeKeyManager.merge_ledger_chains(phone_entries, pc_entries)
    
    assert len(merged) == 3
    assert merged[0].runtime_execution.date == date(2026, 8, 1)
    assert merged[1].runtime_execution.date == date(2026, 8, 2)
    assert merged[2].runtime_execution.date == date(2026, 8, 3)
    
    # Verify merged chain forms an unbroken, valid hash chain
    valid, err = TradeKeyManager.verify_chain_integrity(merged)
    assert valid is True
    assert err is None


def test_invalidation_block_creation_and_verification():
    sup_priv, sup_pub = TradeKeyManager.generate_keypair()
    entry = make_test_entry("CTP-APP-2026-0884", date(2026, 8, 1), 8.0, GENESIS_HASH)
    
    inval_block = TradeKeyManager.create_invalidation_block(
        supervisor_private_key=sup_priv,
        supervisor_trade_id="CTP-JRN-2024-0192",
        target_entry=entry,
        reason_category="ADMINISTRATIVE_SIGNING_ERROR",
        justification="Duplicate entry logged during shift turnover."
    )
    
    valid, err = TradeKeyManager.verify_invalidation_block(sup_pub, inval_block)
    assert valid is True
    assert err is None
    assert inval_block.hours_reversed == 8.0


def test_shared_workstation_cross_practitioner_merge_blocked():
    import pytest
    # Apprentice A's entries
    e_a = make_test_entry("CTP-APP-2026-0884", date(2026, 8, 1), 8.0, GENESIS_HASH)
    
    # Apprentice B's entries from the same shift on a shared workstation
    e_b = make_test_entry("CTP-APP-2026-0042", date(2026, 8, 1), 8.0, GENESIS_HASH)
    
    # Attempting to merge Apprentice B's logs into Apprentice A's vault must raise ValueError
    with pytest.raises(ValueError, match="Cross-practitioner merge violation"):
        TradeKeyManager.merge_ledger_chains([e_a], [e_b])



