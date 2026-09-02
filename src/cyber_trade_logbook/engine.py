"""Trade math, progression accumulator, and fatigue monitoring rules."""

from dataclasses import dataclass
from typing import List, Optional
from datetime import datetime
from .models import LogbookEntry


@dataclass
class DomainProgress:
    d1_perimeter_cloud: float = 0.0
    d2_system_hygiene: float = 0.0
    d3_identity_access: float = 0.0
    d4_vuln_management: float = 0.0
    d5_defensive_grc: float = 0.0

    D1_TARGET: float = 1500.0
    D2_TARGET: float = 2000.0
    D3_TARGET: float = 1500.0
    D4_TARGET: float = 1500.0
    D5_TARGET: float = 1500.0

    @property
    def total_hours(self) -> float:
        return (
            self.d1_perimeter_cloud
            + self.d2_system_hygiene
            + self.d3_identity_access
            + self.d4_vuln_management
            + self.d5_defensive_grc
        )


@dataclass
class TradeAccumulatorResult:
    domain_progress: DomainProgress
    total_ojt_hours: float
    pla_credited_hours: float
    effective_ojt_hours: float
    verified_hours: float
    pending_hours: float
    range_simulation_hours: float
    physical_ledger_hours: float
    digital_ledger_hours: float
    rti_completed_hours: float
    instructional_mentorship_hours: float
    tier_name: str
    wage_step_pct_rjpb: int
    journeyman_eligible: bool
    master_eligible: bool = False


class TradeAccumulator:
    """Calculates statutory hours, caps, and tier standing."""

    MAX_PLA_HOURS = 4000.0
    MAX_RANGE_HOURS = 1000.0
    JOURNEYMAN_OJT_TARGET = 8000.0
    JOURNEYMAN_RTI_TARGET = 576.0
    MASTER_OJT_TARGET = 12000.0
    MASTER_INSTRUCTIONAL_TARGET = 500.0

    @classmethod
    def evaluate(
        cls,
        entries: List[LogbookEntry],
        pla_hours: float = 0.0,
        rti_hours: float = 0.0
    ) -> TradeAccumulatorResult:
        progress = DomainProgress()
        verified_h = 0.0
        pending_h = 0.0
        range_h = 0.0
        physical_h = 0.0
        digital_h = 0.0
        instructional_h = 0.0

        for entry in entries:
            # Skip invalidated entries from active hour accumulation
            if entry.is_invalidated or entry.invalidation is not None:
                continue

            h = entry.runtime_execution.hours_logged
            d = entry.runtime_execution.core_domain
            sub_d = (entry.runtime_execution.sub_domain or "").upper()

            if d == "D1_PERIMETER_CLOUD":
                progress.d1_perimeter_cloud += h
            elif d in ("D2_DETECTION_SOC", "D2_SYSTEM_HYGIENE"):
                progress.d2_system_hygiene += h
            elif d in ("D3_IDENTITY_IAM", "D3_IDENTITY_ACCESS"):
                progress.d3_identity_access += h
            elif d in ("D4_VULN_ATTACK", "D4_VULN_MANAGEMENT"):
                progress.d4_vuln_management += h
            elif d == "D5_DEFENSIVE_GRC":
                progress.d5_defensive_grc += h

            # Track instructional mentorship hours
            if "MENTOR" in sub_d or "SUPERVIS" in sub_d or "INSTRUCT" in sub_d:
                instructional_h += h

            if entry.attestation is not None or (
                entry.physical_attestation and entry.physical_attestation.physical_signature_recorded
            ):
                verified_h += h
            else:
                pending_h += h

            if entry.runtime_execution.environment_type == "Range_Lab":
                range_h += h

            if entry.entry_modality == "physical_bound":
                physical_h += h
            else:
                digital_h += h

        capped_pla = min(pla_hours, cls.MAX_PLA_HOURS)
        capped_range = min(range_h, cls.MAX_RANGE_HOURS)
        total_ojt = progress.total_hours
        effective_ojt = total_ojt + capped_pla

        tier_name = "Tier 1 Apprentice"
        wage_pct = 50

        if effective_ojt >= cls.MASTER_OJT_TARGET:
            tier_name = "Master Practitioner"
            wage_pct = 135
        elif effective_ojt >= cls.JOURNEYMAN_OJT_TARGET and rti_hours >= cls.JOURNEYMAN_RTI_TARGET:
            tier_name = "Licensed Journeyman"
            wage_pct = 100
        elif effective_ojt > 6000.0:
            tier_name = "Tier 4 Apprentice"
            wage_pct = 80
        elif effective_ojt > 4000.0:
            tier_name = "Tier 3 Apprentice"
            wage_pct = 70
        elif effective_ojt > 2000.0:
            tier_name = "Tier 2 Apprentice"
            wage_pct = 60

        journeyman_ready = (
            effective_ojt >= cls.JOURNEYMAN_OJT_TARGET
            and rti_hours >= cls.JOURNEYMAN_RTI_TARGET
            and progress.d1_perimeter_cloud >= progress.D1_TARGET
            and progress.d2_system_hygiene >= progress.D2_TARGET
            and progress.d3_identity_access >= progress.D3_TARGET
            and progress.d4_vuln_management >= progress.D4_TARGET
            and progress.d5_defensive_grc >= progress.D5_TARGET
        )

        master_ready = (
            effective_ojt >= cls.MASTER_OJT_TARGET
            and instructional_h >= cls.MASTER_INSTRUCTIONAL_TARGET
        )

        return TradeAccumulatorResult(
            domain_progress=progress,
            total_ojt_hours=total_ojt,
            pla_credited_hours=capped_pla,
            effective_ojt_hours=effective_ojt,
            verified_hours=verified_h,
            pending_hours=pending_h,
            range_simulation_hours=capped_range,
            physical_ledger_hours=physical_h,
            digital_ledger_hours=digital_h,
            rti_completed_hours=rti_hours,
            instructional_mentorship_hours=instructional_h,
            tier_name=tier_name,
            wage_step_pct_rjpb=wage_pct,
            journeyman_eligible=journeyman_ready,
            master_eligible=master_ready
        )


class FatigueMonitor:
    """Monitors shifts for fatigue, rest violations, and supervisory limits."""

    MAX_SHIFT_HOURS = 14.0
    MIN_REST_HOURS = 10.0
    MAX_SOC_QUEUE_HOURS = 4.0

    @classmethod
    def audit_shift(
        cls,
        entry: LogbookEntry,
        prior_shift_end: Optional[datetime] = None,
        current_shift_start: Optional[datetime] = None
    ) -> List[str]:
        violations = []
        h = entry.runtime_execution.hours_logged

        if h > cls.MAX_SHIFT_HOURS:
            violations.append(
                f"Shift duration ({h} hrs) exceeds the 14-Hour Incident Operational Ceiling."
            )

        if (
            entry.runtime_execution.core_domain in ("D2_DETECTION_SOC", "D2_SYSTEM_HYGIENE")
            and entry.runtime_execution.sub_domain == "LIVE_ALERT_TRIAGE"
            and h > cls.MAX_SOC_QUEUE_HOURS
        ):
            violations.append(
                f"Continuous live alert triage ({h} hrs) exceeds the 4-Hour SOC Vigilance Cap."
            )

        if prior_shift_end and current_shift_start:
            rest_hours = (current_shift_start - prior_shift_end).total_seconds() / 3600.0
            if 0 <= rest_hours < cls.MIN_REST_HOURS:
                violations.append(
                    f"Rest period ({rest_hours:.1f} hrs) violates the mandatory 10-Hour Uninterrupted Rest Cycle."
                )

        return violations
