# Cybersecurity Trade Logbook: User Guide & Operational Architecture

A comprehensive operational guide for Registered Apprentices, Supervising Journeymen, Master Practitioners, and JATC Training Directors using the Universal Digital Logbook.

---

## 1. System Philosophy: Personal Property & Zero Enterprise Footprint

Under **Pillar V** and **Pillar VII** of The Cybersecurity Trade Project, a practitioner's logbook is their statutory personal property (analogous to an airline pilot's flight ledger or a master electrician's work book). 

To eliminate enterprise friction, corporate security audits, and software whitelisting hurdles:
* **Zero Enterprise Footprint:** The application operates entirely on personal mobile devices (iOS/Android) or offline workstations. No software is ever installed on enterprise production infrastructure.
* **100% Client-Side Privacy:** All records, cryptographic hash chains, and keypairs reside in local browser storage (IndexedDB). Zero telemetry, tracking pixels, or third-party cookies are transmitted.
* **True Offline Execution:** Functions seamlessly without internet access inside air-gapped Security Operations Centers (SOCs) or sensitive compartmented information facilities (SCIFs).

---

## 2. Platform Setup & Installation (Mobile vs. Desktop)

The tool requires zero server setup for daily practitioners:

### A. Mobile Phone & Tablet Setup (iOS & Android) : 100% Offline PWA
No terminal commands, compilers, or server processes are required.
1. **Visit Once:** Open `https://the-cyber-trade-project.github.io/logbook/` in Safari (iOS) or Chrome (Android).
2. **Install to Home Screen:**
   * **iPhone/iPad (Safari):** Tap the **Share** button (box with arrow) -> scroll and tap **"Add to Home Screen"** -> tap **Add**.
   * **Android (Chrome):** Tap the **three dots** menu -> tap **"Install App"** (or **"Add to Home Screen"**).
3. **Launch & Offline Use:** Tap the app icon on your device home screen. The Service Worker stores the complete application locally. You can use it in airplane mode, subway commutes, or field sites with zero Wi-Fi or cellular service.

### B. Computer / Laptop Setup (macOS, Windows, Linux)
* **Web Mode:** Open `https://the-cyber-trade-project.github.io/logbook/` in any desktop browser.
* **Air-Gapped Local Host Mode:** If operating in an isolated security lab with zero internet:
  ```bash
  git clone https://github.com/the-cyber-trade-project/logbook.git
  cd logbook
  uv run python -m http.server 8000 --directory public
  ```
  Open `http://localhost:8000` in your browser.

---

## 3. The Unified Single-App Experience (Dual-Role Interface)

The application provides a unified interface where all trade members use the exact same software:

```
+─────────────────────────────────────────────────────────────────────────────+
|                    THE UNIFIED SINGLE-APP EXPERIENCE                        |
+─────────────────────────────────────────────────────────────────────────────+
|                                                                             |
|  • REGISTERED APPRENTICE:                                                   |
|    - Logs operational shifts (Domains 1 through 5).                         |
|    - Transcribes physical SCIF logbook pages.                               |
|    - Tracks progress toward 8,000 OJT hours and 576 RTI hours.              |
|    - Generates Optical QR or NFC batch signing requests for supervisors.    |
|                                                                             |
|  • LICENSED JOURNEYMAN / MASTER PRACTITIONER:                               |
|    - Logs post-licensure Specialty Endorsement runtime (e.g., SE-MED).     |
|    - Accesses "Supervisor Studio" to scan apprentice QR requests.           |
|    - Attests to batch runtime using NFC YubiKeys, FIDO2 keys, or Passkeys.  |
|                                                                             |
|  • JATC TRAINING DIRECTOR & AUDITOR:                                        |
|    - Audits unbroken Merkle hash chains.                                    |
|    - Ingests encrypted quarterly submission bundles.                        |
|    - Formally issues Board Wage Step elevations (Tiers 1 through 4).        |
+─────────────────────────────────────────────────────────────────────────────+
```

---

## 4. Step-by-Step Operational Workflows

### Workflow A: Daily Operational Logging (Digital Modality)
1. At the end of a shift, open the app on your personal phone or computer.
2. Select **Log Hours** from the navigation bar.
3. Enter the shift date, duration (hours), core rotational domain (D1-D5), and specific NIST NICE Work Role.
4. Select the artifact type (e.g., `git_commit_hash`, `change_ticket_id`, `incident_record_id`).
5. Enter the sanitized ticket reference and summary.
   * *Zero-Knowledge Safe Harbor:* Do not enter internal IP addresses, client names, or raw exploit payloads.
6. Tap **Save Operational Entry**. The engine computes a SHA-256 hash linking this entry to the previous entry in an immutable chain.

### Workflow B: Transcribing Physical Bound Ledgers (SCIF / Air-Gap Modality)
1. For operational defense work performed inside a classified SCIF where phones are prohibited:
   * Record the operational task in your serialized, tamper-evident bound physical book.
   * Have your supervising Journeyman physically initial and stamp the page with their official license stamp.
2. Outside the SCIF, open the app and navigate to **Physical**.
3. Enter the physical book serial number, page number, line number, hours, domain, and supervisor license ID.
4. Tap **Save Physical Book Transcription**. The digital ledger records the physical coordinates into your cryptographic chain.


### Workflow C: Supervisor Attestation & Batch Sign-Off (Optical QR & NFC)
When a sprint or week of operational hours is ready for supervisor attestation:

#### Modality 1: Direct NFC YubiKey / Biometric Tap (Same Device)
1. The apprentice opens the **Supervisor** tab on their mobile device.
2. The supervisor reviews the pending hours and domain breakdown on the screen.
3. The supervisor taps **Batch Sign with Trade Key**.
4. The supervisor taps their NFC YubiKey to the back of the apprentice's phone or authenticates via FaceID/TouchID.
5. The hardware token signs the batch digest, locking the entries with an Ed25519 signature.

#### Modality 2: Optical Air-Gap QR Handshake (Device-to-Device)
1. Apprentice selects pending entries and taps **Request Signature QR**.
2. The apprentice's phone displays a compact Signing Request QR code encoding the batch digest.
3. The supervisor opens **Supervisor Studio** on their own personal phone, taps **Scan Apprentice QR**, and points the camera at the apprentice's screen.
4. The supervisor's phone displays the hours and domain breakdown. The supervisor confirms and taps **Sign Batch**.
5. The supervisor's phone displays a **Signature Response QR**.
6. The apprentice scans the supervisor's Signature QR, instantly validating the signature and locking the entries.

---

## 5. Cryptographic Security & Anti-Fraud Invariants

### 1. Tamper-Proof Merkle Hash Chaining
Every entry incorporates the SHA-256 hash of the immediately preceding entry ($H_{\text{prev}}$):
$$\text{Entry Hash} = \text{SHA-256}(\text{log\_id} \,\|\, H_{\text{prev}} \,\|\, \text{practitioner\_id} \,\|\, \text{date} \,\|\, \text{hours} \,\|\, \text{domain} \,\|\, \text{artifact\_ref})$$
* **Result:** Retroactively modifying hours, dates, or artifacts in any past entry breaks the mathematical chain link for all subsequent entries, immediately alerting the JATC during automated audits.

### 2. Identity Binding & Anti-Cloning Protection
* Every entry explicitly binds the practitioner's `trade_id` and legal name into the signed payload.
* When a supervisor signs an entry, their cryptographic signature covers the practitioner's identity.
* If a malicious user copies another apprentice's ledger files and attempts to replace the name or Trade ID with their own, all supervisor signatures become mathematically invalid.

### 3. Prevention of Fake Supervisors & Peer Apprentice Collusion
* Supervisors do not generate self-signed identities. All authorized Journeymen and Masters hold credentials signed by the National Cybersecurity Trade Board Root CA (`NCTB-ROOT-CA`).
* **Role Gating:** The app and Clearinghouse verify that the signer's credential role is `Licensed Journeyman` or `Master Practitioner`. An apprentice credential (`CTP-APP`) attempting to sign hours is strictly rejected.
* **Self-Signing Prohibition:** The engine strictly forbids practitioners from signing their own logbook entries (`supervisor_id !== practitioner_id`).

---

## 6. Exports, JATC Audits & Cyber Insurance Telemetry

### 1. Official JATC Audit Binder (PDF)
* Formatted printable ledger conforming to Department of Labor (DOL) 29 CFR § 29 apprenticeship audit standards.
* Includes 5-domain runtime breakdown charts, supervisor license stamp boxes, physical ledger page reconciliation index, and verification QR codes.

### 2. Zero-Knowledge Actuarial Attestation Feed (JSON)
* Generates an anonymized, cryptographically verified telemetry manifest for enterprise cyber liability insurance underwriters.
* Confirms active Master of Record (MoR) status, supervisory ratio compliance scores (2:1 standard), and total verified operational runtime without exposing customer ticket details or employee PII.

### 3. Encrypted Submission Bundles (`.ctp-bundle`)
* Employs authenticated AES-256-GCM envelope encryption addressed to the National Board Clearinghouse for secure quarterly wage step elevation evaluations.
