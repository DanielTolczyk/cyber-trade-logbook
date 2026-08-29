"""Tests for Trade Mathematical Progression, Caps, and Fatigue Monitoring."""

from datetime import date, datetime, timezone
from cyber_trade_logbook.models import (
    LogbookEntry,
    PractitionerProfile,
    RuntimeExecution,
    DigitalAttestation
)
from cyber_trade_logbook.engine import TradeAccumulator, FatigueMonitor


def make_entry(domain: str, hours: float = 8.0, sub_domain: str = None) -> LogbookEntry:
    return LogbookEntry(
        log_id="urn:uuid:11111111-1111-1111-1111-111111111111",
        entry_modality="digital",
        practitioner=PractitionerProfile(
            trade_id="CTP-APP-2026-0001",
            name="Test Worker",
            tier="Tier 1 Apprentice"
        ),
        runtime_execution=RuntimeExecution(
            date=date(2026, 8, 25),
            hours_logged=hours,
            core_domain=domain,
            sub_domain=sub_domain
        ),
        attestation=DigitalAttestation(
            supervisor_signature="SIG_TEST",
            signed_timestamp=datetime.now(timezone.utc)
        )
    )


def test_domain_accumulation_and_pla_cap():
    # 250 shifts of 8 hours = 2,000 OJT hours
    entries = []
    for _ in range(60):   # 480 hrs
        entries.append(make_entry("D1_PERIMETER_CLOUD", 8.0))
    for _ in range(125):  # 1000 hrs
        entries.append(make_entry("D2_SYSTEM_HYGIENE", 8.0))
    for _ in range(65):   # 520 hrs
        entries.append(make_entry("D3_IDENTITY_ACCESS", 8.0))

    # PLA requested 6000 hours, but statutory cap is 4000 hours
    result = TradeAccumulator.evaluate(entries, pla_hours=6000.0, rti_hours=144.0)

    assert result.total_ojt_hours == 2000.0
    assert result.pla_credited_hours == 4000.0
    assert result.effective_ojt_hours == 6000.0
    assert result.tier_name == "Tier 3 Apprentice"
    assert result.wage_step_pct_rjpb == 70
    assert result.journeyman_eligible is False


def test_journeyman_eligibility_criteria():
    # 1000 shifts of 8 hours = 8,000 OJT hours
    entries = []
    for _ in range(188):  # 1504 hrs D1
        entries.append(make_entry("D1_PERIMETER_CLOUD", 8.0))
    for _ in range(250):  # 2000 hrs D2
        entries.append(make_entry("D2_SYSTEM_HYGIENE", 8.0))
    for _ in range(188):  # 1504 hrs D3
        entries.append(make_entry("D3_IDENTITY_ACCESS", 8.0))
    for _ in range(188):  # 1504 hrs D4
        entries.append(make_entry("D4_VULN_MANAGEMENT", 8.0))
    for _ in range(188):  # 1504 hrs D5
        entries.append(make_entry("D5_DEFENSIVE_GRC", 8.0))

    # 8,016 OJT hours + 576 RTI hours satisfies all 5 domain minimums
    result = TradeAccumulator.evaluate(entries, pla_hours=0.0, rti_hours=576.0)

    assert result.total_ojt_hours == 8016.0
    assert result.tier_name == "Licensed Journeyman"
    assert result.wage_step_pct_rjpb == 100
    assert result.journeyman_eligible is True


def test_fatigue_monitor_violations():
    # Test 1: Exceeds 14-Hour Shift Cap
    long_shift_entry = make_entry("D1_PERIMETER_CLOUD", 16.0)
    violations = FatigueMonitor.audit_shift(long_shift_entry)
    assert any("14-Hour Incident Operational Ceiling" in v for v in violations)

    # Test 2: SOC Live Alert Queue Exceeds 4 Hours
    soc_queue_entry = make_entry("D2_SYSTEM_HYGIENE", 6.0, sub_domain="LIVE_ALERT_TRIAGE")
    violations = FatigueMonitor.audit_shift(soc_queue_entry)
    assert any("4-Hour SOC Vigilance Cap" in v for v in violations)


def test_invalidation_skips_hours_in_accumulator():
    e1 = make_entry("D1_PERIMETER_CLOUD", 8.0)
    e2 = make_entry("D2_SYSTEM_HYGIENE", 8.0)
    e2.is_invalidated = True  # Invalidation tombstone active
    
    entries = [e1, e2]
    result = TradeAccumulator.evaluate(entries, pla_hours=0.0, rti_hours=144.0)
    
    # Only e1 (8.0 hrs) should be counted; e2 (invalidated) must be excluded
    assert result.total_ojt_hours == 8.0
    assert result.domain_progress.d1_perimeter_cloud == 8.0
    assert result.domain_progress.d2_system_hygiene == 0.0


