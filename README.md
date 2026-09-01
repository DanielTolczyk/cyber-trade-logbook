# Cybersecurity Trade Logbook (Universal Digital Ledger)

A privacy-preserving, client-side Progressive Web Application (PWA) and cryptographic verification engine enabling cybersecurity apprentices, Journeymen, and Master Practitioners to maintain portable runtime records under **The Cybersecurity Trade Project** specifications.

---

## 1. Core Capabilities & Architecture

The tool is designed with a **zero-enterprise-footprint** model: the logbook is the statutory personal property of the practitioner, operating completely on personal mobile devices, offline laptops, or within isolated defense enclaves.

### Key Architectural Pillars:

* **Dual-Modality Operational Tracking:**
  * **Digital Log Entries:** Logs operational runtime hours mapped to NIST NICE Work Roles, core rotational domains (D1 through D5), and sanitized artifact references (`git_commit_hash`, `change_ticket_id`, `incident_record_id`, `rule_hash`).
  * **Physical Bound Ledger Transcription:** Dedicated rapid entry workflow for recording hours completed in classified facilities (SCIFs) or air-gapped enclaves, capturing physical book serial numbers, page/line coordinates, and supervisor license stamps.
* **Cryptographic Attestation & Batch Signing:**
  * Ed25519 Trade Key signing for supervisors to attest to runtime batches without exposing private keys.
  * WebAuthn and hardware token integration (NFC / FIDO2 security keys) allowing on-device cross-signing with zero USB mass-storage risk.
* **Statutory Mathematical Enforcement:**
  * Tracks the 8,000-hour rotational distribution across 5 core domains:
    * Domain 1: Perimeter, Cloud & Network Defense (1,500 hrs)
    * Domain 2: Detection Engineering & Incident Triage / SOC (2,000 hrs)
    * Domain 3: Identity, Credential & Access Management / IAM (1,500 hrs)
    * Domain 4: Vulnerability & Attack Surface Management (1,500 hrs)
    * Domain 5: Defensive Governance, Risk & Audit / GRC (1,500 hrs)
  * Enforces the 4,000-hour (50%) Prior Learning Assessment (PLA) residency cap.
  * Tracks Related Technical Instruction (RTI) targets (144 hrs/year, 576 hrs total).
* **Operational Fatigue & Ratio Monitoring:**
  * Automatically flags shifts exceeding the 14-Hour Incident Operational Ceiling.
  * Alerts on continuous live SOC alert triage exceeding the 4-Hour Vigilance Cap.
  * Validates 10-hour uninterrupted rest cycles between emergency operations.
* **Dual Exporters:**
  * **JATC Official PDF Audit Binder:** Generates formatted, printable audit binders for quarterly wage step reviews and Journeyman Licensure Exam defenses.
  * **Zero-Knowledge Actuarial Attestation Feed (JSON):** Produces verified telemetry manifests for cyber liability insurance underwriters without exposing corporate confidential data or practitioner PII.

---

## 2. Directory Structure

```
logbook/
├── public/
│   ├── data/
│   │   └── logbook_specifications.json  # Canonical taxonomy & trade rules
│   ├── index.html                       # Mobile-first responsive PWA UI
│   ├── styles.css                       # High-contrast CSS & print stylesheet
│   ├── app.js                           # IndexedDB & WebCrypto client engine
│   ├── manifest.json                    # Web App manifest for iOS/Android
│   └── sw.js                            # Service Worker for offline-first execution
├── src/
│   └── cyber_trade_logbook/
│       ├── __init__.py
│       ├── models.py                    # Canonical Pydantic schemas (RFC compliant)
│       ├── crypto.py                    # Ed25519 signing, verification & hashing
│       ├── engine.py                    # 8k domain accumulator & fatigue monitor
│       └── cli.py                       # Command-line interface (`ctl-logbook`)
├── tests/
│   ├── test_models.py                   # Schema integrity tests
│   ├── test_crypto.py                   # Ed25519 signature tests
│   └── test_engine.py                   # Domain math, PLA caps & fatigue tests
├── pyproject.toml                       # Python project configuration (uv)
└── README.md
```

---

## 3. Deployment & Setup Guide (Mobile vs. Computer)

The application requires zero server installations on mobile devices. It is distributed as a Progressive Web App (PWA) with client-side offline execution:

### A. Mobile Setup (iOS & Android) : Zero Terminal Commands, 100% Offline

```
[ STEP 1: INITIAL VISIT ]
• Open https://the-cyber-trade-project.github.io/logbook/ on your mobile browser (Safari or Chrome).

[ STEP 2: INSTALL AS STANDALONE APP ]
• On iOS (Safari): Tap the Share button -> tap "Add to Home Screen".
• On Android (Chrome): Tap the three-dot menu -> tap "Install App" (or "Add to Home Screen").

[ STEP 3: OFFLINE EXECUTION ]
• Launch the app from your home screen icon.
• The Service Worker caches all assets. The app functions completely offline without cellular or Wi-Fi connectivity.
```

### B. Computer / Laptop Setup (macOS, Windows, Linux)

* **Option 1 (Web Browser / Desktop PWA):**
  * Open `https://the-cyber-trade-project.github.io/logbook/` in Chrome, Edge, Safari, or Firefox.
  * In Chrome/Edge, click the **Install** icon in the address bar to run it in standalone desktop app mode.
* **Option 2 (Air-Gapped / Local Hosting for Isolated Labs):**
  * For isolated forensic enclaves or air-gapped workstations where external internet access is prohibited:
    ```bash
    git clone https://github.com/the-cyber-trade-project/logbook.git
    cd logbook
    uv run python -m http.server 8000 --directory public
    ```
  * Open `http://localhost:8000` in your local browser.

### C. SCIF Facilities vs. Offline Field Environments

* **Classified Facilities (SCIFs / Closed Areas):**
  * Where mobile devices and smart devices must be checked at the door: Log operational tasks in your **Serialized Physical Bound Book** and have your supervisor stamp entries with their official license stamp (`CTP-JRN-XXXX`).
  * When outside the secure area, transcribe the physical coordinates into your mobile or desktop digital logbook.
* **Offline Field Environments (Basement SOCs / Industrial Plants / Maritime):**
  * Where personal mobile devices are permitted but lack cellular signal or Wi-Fi: The mobile PWA operates completely offline in local IndexedDB storage. All Merkle hash chains, signatures, and progression metrics compute locally in device memory.

---

## 4. Local Development & Automated Test Suite

Managed via `uv`:
```bash
cd logbook
uv run pytest
```

Under The Cybersecurity Trade Project specifications, your logbook is your statutory personal property. Sponsoring employers, training trusts, and trade unions do not maintain centralized custody of your raw operational logs.

* **Sole Custody:** You are solely responsible for maintaining, preserving, and backing up your personal logbook records.
* **Mandatory Backup Routine:** Members must export an encrypted vault backup (`.ctp-vault`) at the conclusion of every working week or sprint to personal offline storage, secondary computers, or private encrypted cloud drives.
* **Separation Safe Harbor:** Sponsoring employers are legally prohibited from withholding or deleting your personal logbook. Maintaining an independent backup protects your accredited career progression against contractual separations, corporate acquisition disputes, or employer IT terminations.

---

## 5. Multi-Device Synchronization & Conflict-Free Merging

To support practitioners working across multiple personal devices (e.g., logging on mobile during shifts and reviewing on desktop at home):
* **Fast-Forward Ingestion:** Non-conflicting sequential entries fast-forward automatically.
* **Deterministic Re-Chaining:** Concurrent draft entries are deduplicated by UUID, sorted chronologically, and re-chained to the latest signed block.
* **Cryptographic Anchor Protection:** Completed supervisor signatures remain permanent, immutable anchors that cannot be overwritten during merges.

---

## 6. Physical Book Intake: JATC Digital Audit Seal Protocol

To eliminate the need to mail paper logbooks or manually re-type thousands of classified shift lines:
1. **In-Person Inspection:** Apprentice presents their physical bound book to the regional JATC Training Director or appointed Master Examiner.
2. **Examiner Digital Seal:** The Examiner verifies page ranges, supervisor stamps, and hours, then signs an official `JATCPhysicalAuditSeal` using their authorized Director Trade Key.
3. **Accredited Milestone:** The seal block is appended to the member's digital ledger and submitted to the Clearinghouse, formally accrediting the physical hours for wage step elevation.

## 7. Cryptographic Vault Security & Inactivity Encryption (AES-256-GCM)

To protect practitioner records on shared workstations, SCIF terminals, or college labs:

* **Authenticated AES-256-GCM Encryption:** Vault records are encrypted at rest using native browser WebCrypto AES-GCM.
* **PBKDF2 Key Derivation:** Encryption keys are derived dynamically from a 4-digit PIN using PBKDF2 with 100,000 iterations of SHA-256 and a 16-byte random salt. The PIN is never saved in LocalStorage, IndexedDB, or server telemetry.
* **Inactivity Auto-Lock:** After 15 minutes of inactivity (or upon manual lock), the active ledger is encrypted into an authenticated ciphertext payload and plaintext records are wiped from browser memory.
* **Zero-Backdoor Hybrid Submissions:** Formal JATC wage elevation audits utilize dual-recipient hybrid envelope encryption (asymmetric public keys) rather than centralized master backdoor passwords.
* **Shared Terminal Safety:** Includes an instant "Unload / Switch Vault" action on the lock screen allowing practitioners to safely clear local memory before another user accesses the workstation.
