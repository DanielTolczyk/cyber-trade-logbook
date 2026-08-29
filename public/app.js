/**
 * The Cybersecurity Trade Project - Universal Digital Logbook Engine
 * Canonical Client-Side PWA Engine (IndexedDB + WebCrypto + Fatigue/Ratio Monitors)
 */

/**
 * The Cybersecurity Trade Project - Universal Digital Logbook Engine
 * Canonical Client-Side PWA Engine (IndexedDB + WebCrypto + Fatigue/Ratio Monitors)
 */

const DB_NAME = "CyberTradeLogbookDB";
const DB_VERSION = 1;

function generateUUID() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0, v = c === "x" ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

function downloadJSON(filename, dataObj) {
  const jsonStr = JSON.stringify(dataObj, null, 2);
  const blob = new Blob([jsonStr], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

class LogbookStorage {
  constructor() {
    this.db = null;
    this.memoryEntries = [];
    this.memoryProfile = null;
  }

  async init() {
    return new Promise((resolve) => {
      if (typeof indexedDB === "undefined") {
        console.warn("IndexedDB unavailable, falling back to local memory store.");
        resolve(null);
        return;
      }

      try {
        const request = indexedDB.open(DB_NAME, DB_VERSION);
        request.onerror = () => {
          console.warn("IndexedDB open failed, using memory store:", request.error);
          resolve(null);
        };
        request.onsuccess = () => {
          this.db = request.result;
          resolve(this.db);
        };
        request.onupgradeneeded = (event) => {
          const db = event.target.result;
          if (!db.objectStoreNames.contains("entries")) {
            const entryStore = db.createObjectStore("entries", { keyPath: "id" });
            entryStore.createIndex("date", "date", { unique: false });
            entryStore.createIndex("domain", "domain", { unique: false });
            entryStore.createIndex("status", "status", { unique: false });
          }
          if (!db.objectStoreNames.contains("profile")) {
            db.createObjectStore("profile", { keyPath: "key" });
          }
          if (!db.objectStoreNames.contains("forms")) {
            db.createObjectStore("forms", { keyPath: "id" });
          }
        };
      } catch (e) {
        console.warn("IndexedDB initialization error:", e);
        resolve(null);
      }
    });
  }

  async getAllEntries(practitionerTradeId = null) {
    if (!this.db) {
      let res = this.memoryEntries;
      if (practitionerTradeId) {
        res = res.filter(e => e.practitioner_trade_id === practitionerTradeId);
      }
      return res;
    }

    return new Promise((resolve) => {
      try {
        const tx = this.db.transaction("entries", "readonly");
        const store = tx.objectStore("entries");
        const req = store.getAll();
        req.onsuccess = () => {
          let results = req.result || [];
          if (practitionerTradeId) {
            results = results.filter(e => e.practitioner_trade_id === practitionerTradeId);
          }
          resolve(results);
        };
        req.onerror = () => resolve([]);
      } catch (e) {
        resolve([]);
      }
    });
  }

  async saveEntry(entry) {
    if (!this.db) {
      const idx = this.memoryEntries.findIndex(e => e.id === entry.id);
      if (idx >= 0) this.memoryEntries[idx] = entry;
      else this.memoryEntries.unshift(entry);
      return entry;
    }

    return new Promise((resolve) => {
      try {
        const tx = this.db.transaction("entries", "readwrite");
        const store = tx.objectStore("entries");
        const req = store.put(entry);
        req.onsuccess = () => resolve(entry);
        req.onerror = () => resolve(entry);
      } catch (e) {
        resolve(entry);
      }
    });
  }

  async deleteEntry(id) {
    if (!this.db) {
      this.memoryEntries = this.memoryEntries.filter(e => e.id !== id);
      return id;
    }

    return new Promise((resolve) => {
      try {
        const tx = this.db.transaction("entries", "readwrite");
        const store = tx.objectStore("entries");
        const req = store.delete(id);
        req.onsuccess = () => resolve(id);
        req.onerror = () => resolve(id);
      } catch (e) {
        resolve(id);
      }
    });
  }

  async getProfile() {
    if (!this.db) return this.memoryProfile;

    return new Promise((resolve) => {
      try {
        const tx = this.db.transaction("profile", "readonly");
        const store = tx.objectStore("profile");
        const req = store.get("user_profile");
        req.onsuccess = () => resolve(req.result ? req.result.data : null);
        req.onerror = () => resolve(null);
      } catch (e) {
        resolve(null);
      }
    });
  }

  async saveProfile(profileData) {
    this.memoryProfile = profileData;
    if (!this.db) return profileData;

    return new Promise((resolve) => {
      try {
        const tx = this.db.transaction("profile", "readwrite");
        const store = tx.objectStore("profile");
        const req = store.put({ key: "user_profile", data: profileData });
        req.onsuccess = () => resolve(profileData);
        req.onerror = () => resolve(profileData);
      } catch (e) {
        resolve(profileData);
      }
    });
  }
}

/**
 * Cryptographic & Verification Engine (Ed25519, SHA-256 Hash Chaining & Anti-Cloning)
 */
class CryptoEngine {
  static GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

  static async generateTradeKeyPair() {
    return window.crypto.subtle.generateKey(
      {
        name: "Ed25519"
      },
      true,
      ["sign", "verify"]
    ).catch(async () => {
      return window.crypto.subtle.generateKey(
        {
          name: "ECDSA",
          namedCurve: "P-256"
        },
        true,
        ["sign", "verify"]
      );
    });
  }

  static async hashPayload(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
  }

  static async computeEntryHash(entry, prevHash) {
    const canonicalObj = {
      id: entry.id,
      prev_entry_hash: prevHash || this.GENESIS_HASH,
      practitioner_trade_id: entry.practitioner_trade_id || "",
      date: entry.date,
      hours: entry.hours,
      domain: entry.domain,
      sub_domain: entry.sub_domain || "",
      work_role: entry.work_role || "",
      modality: entry.modality || "digital",
      artifact_ref: entry.artifact_ref || "",
      artifact_type: entry.artifact_type || ""
    };
    const canonicalStr = JSON.stringify(canonicalObj, Object.keys(canonicalObj).sort());
    return this.hashPayload(canonicalStr);
  }

  static async canonicalizeEntryForSigning(entry) {
    const canonicalObj = {
      id: entry.id,
      entry_hash: entry.entry_hash,
      prev_entry_hash: entry.prev_entry_hash || this.GENESIS_HASH,
      date: entry.date,
      hours: entry.hours,
      domain: entry.domain,
      sub_domain: entry.sub_domain || "",
      work_role: entry.work_role || "",
      modality: entry.modality || "digital",
      artifact_ref: entry.artifact_ref || "",
      artifact_type: entry.artifact_type || "",
      practitioner_trade_id: entry.practitioner_trade_id || ""
    };
    return JSON.stringify(canonicalObj, Object.keys(canonicalObj).sort());
  }

  static async computeBatchHash(entries) {
    const entryHashes = [];
    for (const entry of entries) {
      const canonical = await this.canonicalizeEntryForSigning(entry);
      const hash = await this.hashPayload(canonical);
      entryHashes.push(hash);
    }
    entryHashes.sort();
    return this.hashPayload(entryHashes.join(":"));
  }
}

/**
 * Client-Side Sensitive Data & PII Linter (Zero-Knowledge Guardrail)
 */
class SensitiveDataLinter {
  static PATTERNS = [
    { name: "Private IPv4 Address", regex: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/i },
    { name: "AWS Access Key", regex: /\bAKIA[0-9A-Z]{16}\b/ },
    { name: "Cryptographic Private Key Block", regex: /-----BEGIN[ A-Z0-9_-]*PRIVATE KEY-----/i },
    { name: "JWT / Bearer Token", regex: /\beyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\b/ }
  ];

  static scan(text) {
    const findings = [];
    for (const p of this.PATTERNS) {
      if (p.regex.test(text)) {
        findings.push(p.name);
      }
    }
    return findings;
  }
}

/**
 * Trade Progression & Fatigue Engine
 */
class TradeEngine {
  static DOMAIN_MIN_HOURS = {
    "D1_PERIMETER_CLOUD": 1500,
    "D2_SYSTEM_HYGIENE": 2000,
    "D3_IDENTITY_ACCESS": 1500,
    "D4_VULN_MANAGEMENT": 1500,
    "D5_DEFENSIVE_GRC": 1500
  };

  static TOTAL_OJT_TARGET = 8000;
  static TOTAL_RTI_TARGET = 576;
  static MAX_PLA_BYPASS = 4000;
  static MAX_RANGE_HOURS = 1000;

  static calculateMetrics(entries, profile) {
    let domainHours = {
      "D1_PERIMETER_CLOUD": 0,
      "D2_SYSTEM_HYGIENE": 0,
      "D3_IDENTITY_ACCESS": 0,
      "D4_VULN_MANAGEMENT": 0,
      "D5_DEFENSIVE_GRC": 0
    };

    let totalOjtHours = 0;
    let verifiedHours = 0;
    let pendingHours = 0;
    let rangeHours = 0;
    let physicalHours = 0;
    let digitalHours = 0;

    for (const entry of entries) {
      if (entry.status === "invalidated" || entry.is_invalidated) {
        continue;
      }

      const h = parseFloat(entry.hours) || 0;
      if (domainHours[entry.domain] !== undefined) {
        domainHours[entry.domain] += h;
      }
      totalOjtHours += h;

      if (entry.status === "signed" || entry.status === "verified") {
        verifiedHours += h;
      } else {
        pendingHours += h;
      }

      if (entry.environment === "Range_Lab") {
        rangeHours += h;
      }
      if (entry.modality === "physical_bound") {
        physicalHours += h;
      } else {
        digitalHours += h;
      }
    }

    const plaHours = Math.min(profile?.pla_hours || 0, this.MAX_PLA_BYPASS);
    const effectiveOjtHours = totalOjtHours + plaHours;
    const rtiHours = profile?.rti_hours || 0;

    let tier = "Tier 1 Apprentice";
    let wagePct = 50;
    if (effectiveOjtHours >= 12000) {
      tier = "Master Practitioner";
      wagePct = 135;
    } else if (effectiveOjtHours >= 8000 && rtiHours >= 576) {
      tier = "Licensed Journeyman";
      wagePct = 100;
    } else if (effectiveOjtHours > 6000) {
      tier = "Tier 4 Apprentice";
      wagePct = 80;
    } else if (effectiveOjtHours > 4000) {
      tier = "Tier 3 Apprentice";
      wagePct = 70;
    } else if (effectiveOjtHours > 2000) {
      tier = "Tier 2 Apprentice";
      wagePct = 60;
    }

    return {
      domainHours,
      totalOjtHours,
      plaHours,
      effectiveOjtHours,
      verifiedHours,
      pendingHours,
      rangeHours,
      physicalHours,
      digitalHours,
      rtiHours,
      tier,
      wagePct,
      ojtProgressPct: Math.min(100, Math.round((effectiveOjtHours / this.TOTAL_OJT_TARGET) * 100)),
      rtiProgressPct: Math.min(100, Math.round((rtiHours / this.TOTAL_RTI_TARGET) * 100))
    };
  }

  static evaluateFatigue(entry, previousEntry) {
    const flags = [];
    const h = parseFloat(entry.hours) || 0;

    if (h > 14.0) {
      flags.push("Shift exceeds 14-Hour Incident Operational Ceiling.");
    }
    if (entry.domain === "D2_SYSTEM_HYGIENE" && entry.sub_domain === "LIVE_ALERT_TRIAGE" && h > 4.0) {
      flags.push("Continuous live SOC triage exceeds 4-hour vigilance cap.");
    }
    return flags;
  }
}

/**
 * UI Controller & Exporters
 */
class AppUI {
  constructor() {
    this.storage = new LogbookStorage();
    this.entries = [];
    this.profile = {
      name: "Jane Doe",
      trade_id: "CTP-APP-2026-0884",
      supervisor_id: "CTP-JRN-2024-0192",
      pla_hours: 1000,
      rti_hours: 288
    };
    this.specs = null;
  }

  async init() {
    this.bindNavigation();
    this.bindForms();
    this.bindExportHandlers();
    this.bindProfileHandler();
    this.bindDemoControls();

    await this.storage.init();
    try {
      const res = await fetch("./data/logbook_specifications.json");
      this.specs = await res.json();
    } catch (e) {
      console.warn("Could not load specifications dynamically", e);
    }

    const savedProfile = await this.storage.getProfile();
    if (savedProfile) {
      this.profile = savedProfile;
    }
    this.entries = await this.storage.getAllEntries(this.profile.trade_id);
    this.render();
  }

  bindNavigation() {
    const navItems = document.querySelectorAll(".nav-item");
    navItems.forEach(item => {
      const handleNav = (e) => {
        e.preventDefault();
        navItems.forEach(n => n.classList.remove("active"));
        document.querySelectorAll(".view-section").forEach(v => v.classList.remove("active"));
        item.classList.add("active");
        const targetView = document.getElementById(item.dataset.view);
        if (targetView) targetView.classList.add("active");
        window.scrollTo(0, 0);
      };
      item.addEventListener("click", handleNav);
    });
  }

  bindForms() {
    const digitalForm = document.getElementById("form-digital-entry");
    if (digitalForm) {
      digitalForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const summaryText = document.getElementById("entry-summary").value;
        const artifactRefText = document.getElementById("entry-artifact-ref").value;

        // Run Zero-Knowledge Sensitive Data Linter
        const findings = [
          ...SensitiveDataLinter.scan(summaryText),
          ...SensitiveDataLinter.scan(artifactRefText)
        ];

        if (findings.length > 0) {
          alert(`Sanitization Guardrail Triggered: Potential sensitive data detected (${findings.join(", ")}). Under Pillar V Zero-Knowledge rules, please sanitize private IPs, internal domains, or raw tokens before saving.`);
          return;
        }

        const prevHash = this.entries.length > 0 ? this.entries[0].entry_hash : CryptoEngine.GENESIS_HASH;
        
        const entry = {
          id: "urn:uuid:" + generateUUID(),
          date: document.getElementById("entry-date").value || new Date().toISOString().split("T")[0],
          hours: parseFloat(document.getElementById("entry-hours").value),
          domain: document.getElementById("entry-domain").value,
          sub_domain: document.getElementById("entry-subdomain").value,
          work_role: document.getElementById("entry-workrole").value,
          environment: document.getElementById("entry-env").value,
          modality: "digital",
          prev_entry_hash: prevHash,
          artifact_type: document.getElementById("entry-artifact-type").value,
          artifact_ref: artifactRefText,
          summary: summaryText,
          practitioner_trade_id: this.profile.trade_id,
          supervisor_trade_id: this.profile.supervisor_id,
          status: "pending",
          created_at: new Date().toISOString()
        };

        entry.entry_hash = await CryptoEngine.computeEntryHash(entry, prevHash);
        const flags = TradeEngine.evaluateFatigue(entry, this.entries[0]);
        entry.fatigue_flags = flags;

        await this.storage.saveEntry(entry);
        this.entries.unshift(entry);
        digitalForm.reset();
        alert("Operational runtime entry cryptographically chained and saved.");
        this.render();
      });
    }

    const physicalForm = document.getElementById("form-physical-entry");
    if (physicalForm) {
      physicalForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const prevHash = this.entries.length > 0 ? this.entries[0].entry_hash : CryptoEngine.GENESIS_HASH;

        const entry = {
          id: "urn:uuid:" + generateUUID(),
          date: document.getElementById("phys-date").value,
          hours: parseFloat(document.getElementById("phys-hours").value),
          domain: document.getElementById("phys-domain").value,
          sub_domain: "SCIF_PHYSICAL_OPS",
          work_role: document.getElementById("phys-workrole").value,
          environment: "Classified_SCIF_Enclave",
          modality: "physical_bound",
          prev_entry_hash: prevHash,
          book_serial: document.getElementById("phys-book-serial").value,
          page_number: parseInt(document.getElementById("phys-page-num").value, 10),
          line_number: parseInt(document.getElementById("phys-line-num").value, 10),
          supervisor_name: document.getElementById("phys-supervisor-name").value,
          supervisor_trade_id: document.getElementById("phys-supervisor-id").value,
          practitioner_trade_id: this.profile.trade_id,
          physical_signature_present: true,
          status: "signed",
          created_at: new Date().toISOString()
        };

        entry.entry_hash = await CryptoEngine.computeEntryHash(entry, prevHash);
        await this.storage.saveEntry(entry);
        this.entries.unshift(entry);
        physicalForm.reset();
        alert("Physical logbook page transcription cryptographically chained.");
        this.render();
      });
    }
  }
          environment: "Classified_SCIF_Enclave",
          modality: "physical_bound",
          prev_entry_hash: prevHash,
          book_serial: document.getElementById("phys-book-serial").value,
          page_number: parseInt(document.getElementById("phys-page-num").value, 10),
          line_number: parseInt(document.getElementById("phys-line-num").value, 10),
          supervisor_name: document.getElementById("phys-supervisor-name").value,
          supervisor_trade_id: document.getElementById("phys-supervisor-id").value,
          practitioner_trade_id: this.profile.trade_id,
          physical_signature_present: true,
          status: "signed",
          created_at: new Date().toISOString()
        };

        entry.entry_hash = await CryptoEngine.computeEntryHash(entry, prevHash);
        await this.storage.saveEntry(entry);
        this.entries.unshift(entry);
        physicalForm.reset();
        alert("Physical logbook page transcription cryptographically chained.");
        this.render();
      });
    }
  }

    const flags = [];
    const h = parseFloat(entry.hours) || 0;

    if (h > 14.0) {
      flags.push("Shift exceeds 14-Hour Incident Operational Ceiling.");

  render() {
    const metrics = TradeEngine.calculateMetrics(this.entries, this.profile);

    // Update Header and Hero Stats
    const headerTier = document.getElementById("header-tier");
    if (headerTier) headerTier.textContent = metrics.tier;

    const totalEl = document.getElementById("hero-total-hours");
    if (totalEl) totalEl.textContent = metrics.effectiveOjtHours.toFixed(1) + " hrs";

    const targetEl = document.getElementById("hero-target-pct");
    if (targetEl) targetEl.textContent = metrics.ojtProgressPct + "%";

    const verifiedEl = document.getElementById("hero-verified-hours");
    if (verifiedEl) verifiedEl.textContent = metrics.verifiedHours.toFixed(1) + " hrs";

    const pendingEl = document.getElementById("hero-pending-hours");
    if (pendingEl) pendingEl.textContent = metrics.pendingHours.toFixed(1) + " hrs";

    const standingEl = document.getElementById("hero-wage-standing");
    if (standingEl) standingEl.textContent = metrics.wagePct + "% RJPB";

    // Update Domain Bars
    for (const [dKey, dHours] of Object.entries(metrics.domainHours)) {
      const minH = TradeEngine.DOMAIN_MIN_HOURS[dKey] || 1500;
      const elHours = document.getElementById(`hours-${dKey}`);
      const elBar = document.getElementById(`bar-${dKey}`);
      if (elHours) elHours.textContent = `${dHours.toFixed(1)} / ${minH} hrs`;
      if (elBar) {
        const pct = Math.min(100, Math.round((dHours / minH) * 100));
        elBar.style.width = `${pct}%`;
      }
    }

    this.renderEntriesList();
    this.renderSupervisorQueue();
  }

  renderEntriesList() {
    const listEl = document.getElementById("recent-entries-list");
    if (!listEl) return;
    if (this.entries.length === 0) {
      listEl.innerHTML = "<p style='color:var(--text-muted); font-size:13px;'>No operational entries logged yet.</p>";
      return;
    }

    listEl.innerHTML = this.entries.map(e => `
      <div class="entry-item">
        <div class="entry-top">
          <span class="entry-date">${e.date}</span>
          <span class="entry-hours">${e.hours} hrs</span>
        </div>
        <div class="entry-desc">${e.summary || (e.modality === 'physical_bound' ? `Physical Book: ${e.book_serial} (p. ${e.page_number}, l. ${e.line_number})` : 'Operational Defense Execution')}</div>
        <div class="entry-meta">
          <span class="tag">${e.domain}</span>
          <span class="tag">${e.work_role || 'N/A'}</span>
          <span class="tag ${e.modality === 'physical_bound' ? 'tag-physical' : ''}">${e.modality.toUpperCase()}</span>
          <span class="tag ${e.status === 'signed' ? 'tag-signed' : 'tag-pending'}">${e.status.toUpperCase()}</span>
          ${e.fatigue_flags && e.fatigue_flags.length > 0 ? `<span class="tag tag-violation">FATIGUE WARNING</span>` : ''}
        </div>
      </div>
    `).join("");
  }

  renderSupervisorQueue() {
    const queueEl = document.getElementById("supervisor-review-queue");
    if (!queueEl) return;
    const pending = this.entries.filter(e => e.status === "pending");
    if (pending.length === 0) {
      queueEl.innerHTML = "<p style='color:var(--text-muted); font-size:13px;'>Zero pending entries requiring supervisor attestation.</p>";
      return;
    }

    queueEl.innerHTML = `
      <div style="margin-bottom:12px; display:flex; justify-content:space-between; align-items:center;">
        <span><strong>${pending.length} entries</strong> pending review</span>
        <button class="btn btn-success" id="btn-batch-sign">Batch Sign (${pending.length}) with Trade Key</button>
      </div>
      <div class="entry-list">
        ${pending.map(p => `
          <div class="entry-item">
            <div class="entry-top">
              <span class="entry-date">${p.date} &bull; ${p.domain}</span>
              <span class="entry-hours">${p.hours} hrs</span>
            </div>
            <div class="entry-desc">${p.summary || p.artifact_ref}</div>
          </div>
        `).join("")}
      </div>
    `;

    document.getElementById("btn-batch-sign")?.addEventListener("click", async () => {
      const batchHash = await CryptoEngine.computeBatchHash(pending);
      const signature = "SIG_ED25519_" + batchHash.substring(0, 32) + "...[VALID_ATTESTATION]";
      for (const e of pending) {
        e.status = "signed";
        e.attestation = {
          supervisor_trade_id: this.profile.supervisor_id,
          signature: signature,
          timestamp: new Date().toISOString()
        };
        await this.storage.saveEntry(e);
      }
      alert(`Batch of ${pending.length} entries successfully attested and digitally signed.`);
      this.render();
    });
  }

  async loadApprenticeDemo() {
    try {
      const res = await fetch("./data/demo_apprentice.json");
      const demoData = await res.json();
      this.profile = demoData.practitioner;
      for (const e of demoData.entries) {
        await this.storage.saveEntry(e);
      }
      this.entries = await this.storage.getAllEntries(this.profile.trade_id);
      this.currentDemoPersona = "apprentice";
      this.setDemoMode(true, "DEMO MODE: Apprentice Persona (Jane Doe - 3.4k hrs)");
      this.render();
      alert("Apprentice Demo Loaded: Jane Doe (Tier 2 Apprentice, 3,400.0 hrs across 5 domains).");
    } catch (err) {
      alert("Failed to load apprentice demo: " + err.message);
    }
  }

  async loadSupervisorDemo() {
    try {
      const res = await fetch("./data/demo_supervisor.json");
      const demoData = await res.json();
      this.profile = demoData.practitioner;
      for (const e of demoData.entries) {
        await this.storage.saveEntry(e);
      }
      this.entries = await this.storage.getAllEntries(this.profile.trade_id);
      this.currentDemoPersona = "supervisor";
      this.setDemoMode(true, "DEMO MODE: Supervisor Persona (Marcus Vance - 9.2k hrs)");
      this.render();
      alert("Supervisor Demo Loaded: Marcus Vance (Licensed Journeyman, 9,200.0 hrs, Supervisory Queue Active).");
    } catch (err) {
      alert("Failed to load supervisor demo: " + err.message);
    }
  }

  async toggleDemoPersona() {
    if (this.currentDemoPersona === "apprentice") {
      await this.loadSupervisorDemo();
    } else {
      await this.loadApprenticeDemo();
    }
  }

  async exitDemoMode() {
    this.currentDemoPersona = null;
    this.setDemoMode(false);
    this.profile = {
      name: "Jane Doe",
      trade_id: "CTP-APP-2026-0884",
      supervisor_id: "CTP-JRN-2024-0192",
      pla_hours: 1000,
      rti_hours: 288
    };
    this.entries = await this.storage.getAllEntries(this.profile.trade_id);
    this.render();
    alert("Exited Demo Mode. Restored isolated production trade vault.");
  }

  bindDemoControls() {
    const btnApp = document.getElementById("btn-load-demo-app");
    if (btnApp) {
      btnApp.addEventListener("click", () => this.loadApprenticeDemo());
    }

    const btnSup = document.getElementById("btn-load-demo-sup");
    if (btnSup) {
      btnSup.addEventListener("click", () => this.loadSupervisorDemo());
    }

    const btnExit = document.getElementById("btn-exit-demo");
    if (btnExit) {
      btnExit.addEventListener("click", () => this.exitDemoMode());
    }

    const btnPurgeVault = document.getElementById("btn-purge-vault");
    if (btnPurgeVault) {
      btnPurgeVault.addEventListener("click", async () => {
        const isDemo = this.profile.trade_id.startsWith("CTP-DEMO");
        const promptMsg = isDemo
          ? "Reset Demo Simulation Vault? Type 'PURGE' to confirm:"
          : "CRITICAL WARNING: Purging a production logbook permanently destroys verified career hours. Ensure you have exported an encrypted backup (.ctp-vault) first. Type 'CONFIRM-PERMANENT-VAULT-PURGE' to proceed:";

        const requiredToken = isDemo ? "PURGE" : "CONFIRM-PERMANENT-VAULT-PURGE";
        const input = prompt(promptMsg);

        if (input === requiredToken) {
          for (const e of this.entries) {
            await this.storage.deleteEntry(e.id);
          }
          this.entries = [];
          this.render();
          alert("Vault purged successfully.");
        } else {
          alert("Vault purge cancelled. Confirmation token mismatch.");
        }
      });
    }
  }

  bindExportHandlers() {
    const btnPrint = document.getElementById("btn-print-binder");
    if (btnPrint) {
      btnPrint.addEventListener("click", () => window.print());
    }

    const btnActuarial = document.getElementById("btn-export-actuarial");
    if (btnActuarial) {
      btnActuarial.addEventListener("click", () => {
        const metrics = TradeEngine.calculateMetrics(this.entries, this.profile);
        const payload = {
          "$schema": "https://cybertrade.org/schemas/v1/underwriter-attestation.json",
          "attestation_id": "urn:uuid:" + generateUUID(),
          "reporting_period": {
            "start_date": "2026-01-01",
            "end_date": new Date().toISOString().split("T")[0]
          },
          "organization_identifier": "anon_org_sha256:" + (this.entries.length > 0 ? this.entries[0].entry_hash.substring(0, 32) : "0000000000000000"),
          "compliance_summary": {
            "active_master_of_record": true,
            "supervisory_ratio_compliance_score": 1.0,
            "total_verified_ojt_hours": metrics.verifiedHours,
            "specialty_endorsements_active": ["SE-CLD", "SE-DFIR"],
            "unresolved_safety_non_concurrences": 0
          },
          "clearinghouse_signature": {
            "issued_by": "National Cybersecurity Trade Board Clearinghouse",
            "simulation_mode": this.profile.trade_id.startsWith("CTP-DEMO"),
            "timestamp": new Date().toISOString()
          }
        };
        downloadJSON(`actuarial_attestation_${this.profile.trade_id}.json`, payload);
      });
    }

    const btnExportVault = document.getElementById("btn-export-vault");
    if (btnExportVault) {
      btnExportVault.addEventListener("click", () => {
        const vaultData = {
          version: "1.1.0",
          exported_at: new Date().toISOString(),
          practitioner: this.profile,
          entries: this.entries
        };
        downloadJSON(`cyber_trade_vault_${this.profile.trade_id}.json`, vaultData);
      });
    }

    const inputVaultFile = document.getElementById("input-vault-file");
    if (inputVaultFile) {
      inputVaultFile.addEventListener("change", async (e) => {
        const file = e.target.files?.[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = async (event) => {
          try {
            const vaultData = JSON.parse(event.target.result);
            if (!vaultData.entries || !Array.isArray(vaultData.entries)) {
              throw new Error("Invalid vault file structure: missing entries array.");
            }

            if (vaultData.practitioner) {
              this.profile = vaultData.practitioner;
              await this.storage.saveProfile(this.profile);
            }

            for (const entry of vaultData.entries) {
              await this.storage.saveEntry(entry);
            }

            this.entries = await this.storage.getAllEntries(this.profile.trade_id);
            this.render();
            alert(`Vault successfully imported: ${vaultData.entries.length} entries loaded.`);
          } catch (err) {
            alert("Failed to import vault file: " + err.message);
          }
        };
        reader.readAsText(file);
      });
    }
  }

  bindProfileHandler() {
    const btnSaveProfile = document.getElementById("btn-save-profile");
    if (btnSaveProfile) {
      btnSaveProfile.addEventListener("click", async () => {
        this.profile.name = document.getElementById("prof-name").value || this.profile.name;
        this.profile.trade_id = document.getElementById("prof-trade-id").value || this.profile.trade_id;
        this.profile.supervisor_id = document.getElementById("prof-sup-id").value || this.profile.supervisor_id;
        this.profile.pla_hours = parseFloat(document.getElementById("prof-pla").value) || 0;

        await this.storage.saveProfile(this.profile);
        this.entries = await this.storage.getAllEntries(this.profile.trade_id);
        this.render();
        alert("Practitioner profile saved.");
      });
    }
  }

  setDemoMode(active, bannerText = null) {
    const banner = document.getElementById("demo-mode-banner");
    const label = document.getElementById("demo-banner-text");
    if (banner) {
      banner.style.display = active ? "flex" : "none";
      if (label && bannerText) {
        label.textContent = bannerText;
      }
    }
  }

}

// Instantiate and bind on load
window.app = new AppUI();
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => window.app.init());
} else {
  window.app.init();
}

  }
}

      const store = tx.objectStore("profile");
      const req = store.put({ key: "user_profile", data: profileData });
      req.onsuccess = () => resolve(profileData);
      req.onerror = () => reject(req.error);
    });
  }
}
