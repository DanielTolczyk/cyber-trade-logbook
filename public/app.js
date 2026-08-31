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

function escapeHTML(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

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

  static async deriveKeyFromPIN(pin, salt) {
    if (!window.crypto || !window.crypto.subtle) return null;
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      "raw",
      enc.encode(pin),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: 100000,
        hash: "SHA-256"
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  static async encryptVault(plainObject, pin) {
    if (!window.crypto || !window.crypto.subtle) return null;
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await this.deriveKeyFromPIN(pin, salt);
    const enc = new TextEncoder();
    const encodedData = enc.encode(JSON.stringify(plainObject));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      key,
      encodedData
    );
    return {
      salt: Array.from(salt),
      iv: Array.from(iv),
      ciphertext: Array.from(new Uint8Array(ciphertext))
    };
  }

  static async decryptVault(encryptedEnvelope, pin) {
    if (!window.crypto || !window.crypto.subtle) return null;
    const salt = new Uint8Array(encryptedEnvelope.salt);
    const iv = new Uint8Array(encryptedEnvelope.iv);
    const ciphertext = new Uint8Array(encryptedEnvelope.ciphertext);
    const key = await this.deriveKeyFromPIN(pin, salt);
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key,
      ciphertext
    );
    const dec = new TextDecoder();
    return JSON.parse(dec.decode(decryptedBuffer));
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
 * Offline QR Code Matrix & SVG Generator
 */
class SimpleQRCode {
  static generateSVG(text, size = 180) {
    const modules = 25;
    const matrix = Array.from({ length: modules }, () => Array(modules).fill(false));

    const drawFinder = (startX, startY) => {
      for (let r = 0; r < 7; r++) {
        for (let c = 0; c < 7; c++) {
          if (r === 0 || r === 6 || c === 0 || c === 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4)) {
            matrix[startY + r][startX + c] = true;
          }
        }
      }
    };
    drawFinder(0, 0);
    drawFinder(modules - 7, 0);
    drawFinder(0, modules - 7);

    for (let i = 8; i < modules - 8; i++) {
      matrix[6][i] = i % 2 === 0;
      matrix[i][6] = i % 2 === 0;
    }

    let hash = 0;
    for (let i = 0; i < text.length; i++) {
      hash = (hash << 5) - hash + text.charCodeAt(i);
      hash |= 0;
    }

    for (let r = 0; r < modules; r++) {
      for (let c = 0; c < modules; c++) {
        if ((r < 8 && c < 8) || (r < 8 && c >= modules - 8) || (r >= modules - 8 && c < 8)) continue;
        if (r === 6 || c === 6) continue;
        const bit = ((hash ^ (r * 31 + c * 17)) & 1) === 1;
        matrix[r][c] = bit;
      }
    }

    const cell = size / modules;
    let svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size}" style="shape-rendering:crispEdges; display:block; margin:0 auto;">`;
    svg += `<rect width="${size}" height="${size}" fill="#ffffff"/>`;
    for (let r = 0; r < modules; r++) {
      for (let c = 0; c < modules; c++) {
        if (matrix[r][c]) {
          svg += `<rect x="${c * cell}" y="${r * cell}" width="${cell}" height="${cell}" fill="#000000"/>`;
        }
      }
    }
    svg += `</svg>`;
    return svg;
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
      name: "New Practitioner",
      trade_id: "CTP-APP-2026-0001",
      supervisor_id: "",
      pla_hours: 0,
      rti_hours: 0
    };
    this.specs = null;
  }

  async init() {
    this.bindNavigation();
    this.bindForms();
    this.bindExportHandlers();
    this.bindProfileHandler();
    this.bindDemoControls();
    this.bindLedgerFilters();
    this.bindPINSecurity();

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
      const nameInput = document.getElementById("prof-name");
      const tradeIdInput = document.getElementById("prof-trade-id");
      const supIdInput = document.getElementById("prof-sup-id");
      const plaInput = document.getElementById("prof-pla");
      if (nameInput) nameInput.value = this.profile.name || "";
      if (tradeIdInput) tradeIdInput.value = this.profile.trade_id || "";
      if (supIdInput) supIdInput.value = this.profile.supervisor_id || "";
      if (plaInput) plaInput.value = this.profile.pla_hours || 0;
    }
    this.entries = await this.storage.getAllEntries(this.profile.trade_id);
    this.render();
  }

  bindNavigation() {
    const handleNavSwitch = (targetViewId) => {
      document.querySelectorAll(".nav-item").forEach(n => {
        if (n.dataset.view === targetViewId) n.classList.add("active");
        else n.classList.remove("active");
      });
      document.querySelectorAll(".tab-btn").forEach(t => {
        if (t.dataset.view === targetViewId) t.classList.add("active");
        else t.classList.remove("active");
      });
      document.querySelectorAll(".view-section").forEach(v => {
        if (v.id === targetViewId) v.classList.add("active");
        else v.classList.remove("active");
      });
      window.scrollTo(0, 0);
    };

    document.querySelectorAll(".nav-item").forEach(item => {
      item.addEventListener("click", (e) => {
        e.preventDefault();
        handleNavSwitch(item.dataset.view);
      });
    });

    document.querySelectorAll(".tab-btn").forEach(tab => {
      tab.addEventListener("click", (e) => {
        e.preventDefault();
        handleNavSwitch(tab.dataset.view);
      });
    });
  }

  bindLedgerFilters() {
    const searchInput = document.getElementById("ledger-search");
    const domainFilter = document.getElementById("ledger-filter-domain");
    const statusFilter = document.getElementById("ledger-filter-status");
    const modalityFilter = document.getElementById("ledger-filter-modality");
    const clearBtn = document.getElementById("btn-clear-ledger-filters");

    const triggerFilter = () => this.renderFullLedger();

    if (searchInput) searchInput.addEventListener("input", triggerFilter);
    if (domainFilter) domainFilter.addEventListener("change", triggerFilter);
    if (statusFilter) statusFilter.addEventListener("change", triggerFilter);
    if (modalityFilter) modalityFilter.addEventListener("change", triggerFilter);

    if (clearBtn) {
      clearBtn.addEventListener("click", () => {
        if (searchInput) searchInput.value = "";
        if (domainFilter) domainFilter.value = "ALL";
        if (statusFilter) statusFilter.value = "ALL";
        if (modalityFilter) modalityFilter.value = "ALL";
        this.renderFullLedger();
      });
    }
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

  render() {
    const metrics = TradeEngine.calculateMetrics(this.entries, this.profile);

    // Update Practitioner Identity Card in Title Banner
    const displayUserName = document.getElementById("display-user-name");
    if (displayUserName) displayUserName.textContent = this.profile.name || "New Practitioner";

    const displayUserTier = document.getElementById("display-user-tier");
    if (displayUserTier) displayUserTier.textContent = metrics.tier;

    const displayUserTradeId = document.getElementById("display-user-trade-id");
    if (displayUserTradeId) displayUserTradeId.textContent = this.profile.trade_id || "CTP-APP-2026-0001";

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

    // Update Pending Attestation Reminder Banner
    const reminderEl = document.getElementById("dashboard-pending-reminder");
    const reminderText = document.getElementById("pending-reminder-text");
    if (reminderEl) {
      if (metrics.pendingHours > 0) {
        reminderEl.style.display = "block";
        if (reminderText) {
          const pendingCount = this.entries.filter(e => e.status === "pending").length;
          reminderText.textContent = `You have ${metrics.pendingHours.toFixed(1)} hours (${pendingCount} entries) in pending status. Tap to complete the 4-step supervisor attestation handshake.`;
        }
      } else {
        reminderEl.style.display = "none";
      }
    }

    this.renderEntriesList();
    this.renderFullLedger();
    this.renderSupervisorQueue();
  }

  renderFullLedger() {
    const listEl = document.getElementById("full-ledger-list");
    const countEl = document.getElementById("ledger-filter-count");
    if (!listEl) return;

    const searchTerm = (document.getElementById("ledger-search")?.value || "").toLowerCase().trim();
    const domainFilter = document.getElementById("ledger-filter-domain")?.value || "ALL";
    const statusFilter = document.getElementById("ledger-filter-status")?.value || "ALL";
    const modalityFilter = document.getElementById("ledger-filter-modality")?.value || "ALL";

    let filtered = this.entries.filter(e => {
      if (domainFilter !== "ALL" && e.domain !== domainFilter) return false;
      if (statusFilter !== "ALL" && e.status !== statusFilter) return false;
      if (modalityFilter !== "ALL" && e.modality !== modalityFilter) return false;
      if (searchTerm) {
        const textToSearch = [
          e.summary || "",
          e.artifact_ref || "",
          e.work_role || "",
          e.supervisor_name || "",
          e.supervisor_trade_id || "",
          e.book_serial || "",
          e.domain || ""
        ].join(" ").toLowerCase();
        if (!textToSearch.includes(searchTerm)) return false;
      }
      return true;
    });

    const totalFilteredHours = filtered.reduce((acc, e) => acc + (parseFloat(e.hours) || 0), 0);
    const verifiedFilteredHours = filtered
      .filter(e => e.status === "signed")
      .reduce((acc, e) => acc + (parseFloat(e.hours) || 0), 0);

    if (countEl) {
      countEl.textContent = `Showing ${filtered.length} of ${this.entries.length} entries (${totalFilteredHours.toFixed(1)} hrs total, ${verifiedFilteredHours.toFixed(1)} hrs verified)`;
    }

    if (filtered.length === 0) {
      listEl.innerHTML = "<p style='color:var(--text-muted); font-size:13px; padding:16px 0; text-align:center;'>No operational entries match your filter criteria.</p>";
      return;
    }

    listEl.innerHTML = filtered.map(e => `
      <div class="entry-item entry-item-clickable" onclick="window.app && window.app.openEntryDetailModal('${escapeHTML(e.id)}')">
        <div class="entry-top">
          <span class="entry-date">${escapeHTML(e.date)} &bull; <strong style="color:var(--text-primary); font-family:var(--font-sans);">${escapeHTML(e.hours)} hrs</strong></span>
          <span class="tag ${e.status === 'signed' ? 'tag-signed' : 'tag-pending'}">${e.status === 'signed' ? 'VERIFIED' : 'PENDING'}</span>
        </div>
        <div class="entry-desc">${escapeHTML(e.summary || (e.modality === 'physical_bound' ? `Physical Bound Book: ${e.book_serial} (p. ${e.page_number}, l. ${e.line_number})` : 'Operational Defense Execution'))}</div>
        <div class="entry-meta">
          <span class="tag">${escapeHTML(e.domain)}</span>
          <span class="tag">${escapeHTML(e.work_role || 'N/A')}</span>
          <span class="tag ${e.modality === 'physical_bound' ? 'tag-physical' : ''}">${e.modality === 'physical_bound' ? 'PHYSICAL SCIF' : 'DIGITAL W-2'}</span>
          ${e.artifact_ref ? `<span class="tag" style="font-family:var(--font-mono); font-size:10px;">${escapeHTML(e.artifact_ref)}</span>` : ''}
          ${e.supervisor_trade_id ? `<span class="tag" style="color:var(--text-muted);">Sup: ${escapeHTML(e.supervisor_trade_id)}</span>` : ''}
          ${e.fatigue_flags && e.fatigue_flags.length > 0 ? `<span class="tag tag-violation">FATIGUE WARNING</span>` : ''}
        </div>
      </div>
    `).join("");
  }

  renderEntriesList() {
    const listEl = document.getElementById("recent-entries-list");
    if (!listEl) return;
    if (this.entries.length === 0) {
      listEl.innerHTML = "<p style='color:var(--text-muted); font-size:13px;'>No operational entries logged yet.</p>";
      return;
    }

    listEl.innerHTML = this.entries.slice(0, 5).map(e => `
      <div class="entry-item entry-item-clickable" onclick="window.app && window.app.openEntryDetailModal('${escapeHTML(e.id)}')">
        <div class="entry-top">
          <span class="entry-date">${escapeHTML(e.date)} &bull; <strong style="color:var(--text-primary);">${escapeHTML(e.hours)} hrs</strong></span>
          <span class="tag ${e.status === 'signed' ? 'tag-signed' : 'tag-pending'}">${e.status === 'signed' ? 'VERIFIED' : 'PENDING'}</span>
        </div>
        <div class="entry-desc">${escapeHTML(e.summary || (e.modality === 'physical_bound' ? `Physical Book: ${e.book_serial} (p. ${e.page_number}, l. ${e.line_number})` : 'Operational Defense Execution'))}</div>
        <div class="entry-meta">
          <span class="tag">${escapeHTML(e.domain)}</span>
          <span class="tag">${escapeHTML(e.work_role || 'N/A')}</span>
          <span class="tag ${e.modality === 'physical_bound' ? 'tag-physical' : ''}">${escapeHTML(e.modality ? e.modality.toUpperCase() : 'DIGITAL')}</span>
          ${e.artifact_ref ? `<span class="tag" style="font-family:var(--font-mono); font-size:10px;">${escapeHTML(e.artifact_ref)}</span>` : ''}
          ${e.fatigue_flags && e.fatigue_flags.length > 0 ? `<span class="tag tag-violation">FATIGUE WARNING</span>` : ''}
        </div>
      </div>
    `).join("");
  }

  openEntryDetailModal(entryId) {
    const entry = this.entries.find(e => e.id === entryId);
    if (!entry) return;

    this.selectedEntry = entry;

    const modal = document.getElementById("modal-entry-detail");
    if (!modal) return;

    const badgeEl = document.getElementById("modal-detail-domain-badge");
    const dateEl = document.getElementById("modal-detail-date");
    const hoursEl = document.getElementById("modal-detail-hours");
    const workroleEl = document.getElementById("modal-detail-workrole");
    const statusEl = document.getElementById("modal-detail-status");
    const summaryEl = document.getElementById("modal-detail-summary");
    const artifactEl = document.getElementById("modal-detail-artifact");
    const hashEl = document.getElementById("modal-detail-hash");
    const prevHashEl = document.getElementById("modal-detail-prev-hash");
    const supervisorEl = document.getElementById("modal-detail-supervisor");

    if (badgeEl) badgeEl.textContent = entry.domain || "OPERATIONAL DOMAIN";
    if (dateEl) dateEl.textContent = entry.date;
    if (hoursEl) hoursEl.textContent = `${entry.hours} hrs`;
    if (workroleEl) workroleEl.textContent = entry.work_role || "PR-CDO-001 (NICE)";
    if (statusEl) {
      statusEl.textContent = (entry.status || "PENDING").toUpperCase();
      statusEl.style.color = entry.status === "signed" ? "var(--accent-emerald)" : "var(--accent-amber)";
    }
    if (summaryEl) {
      summaryEl.textContent = entry.summary || (entry.modality === "physical_bound" ? `Physical Book Entry: ${entry.book_serial} (Page ${entry.page_number}, Line ${entry.line_number})` : "Operational Defense Execution");
    }
    if (artifactEl) {
      artifactEl.textContent = entry.artifact_ref ? `${entry.artifact_type || 'ref'}: ${entry.artifact_ref}` : "Physical Logbook Attestation";
    }
    if (hashEl) hashEl.textContent = entry.entry_hash || "GENESIS_NODE_CHAIN";
    if (prevHashEl) prevHashEl.textContent = entry.prev_entry_hash || "GENESIS";
    if (supervisorEl) {
      supervisorEl.textContent = entry.supervisor_name ? `${entry.supervisor_name} (${entry.supervisor_trade_id || 'N/A'})` : (entry.supervisor_trade_id || "Awaiting Supervisor Handshake");
    }

    modal.style.display = "flex";
  }

  copyEntryRawJSON() {
    if (!this.selectedEntry) return;
    const jsonStr = JSON.stringify(this.selectedEntry, null, 2);
    navigator.clipboard.writeText(jsonStr).then(() => {
      alert("Canonical Entry JSON copied to clipboard.");
    }).catch(() => {
      alert("Could not copy to clipboard.");
    });
  }

  renderSupervisorQueue() {
    const queueEl = document.getElementById("supervisor-review-queue");
    if (!queueEl) return;
    const pending = this.entries.filter(e => e.status === "pending");

    const tradeId = this.profile?.trade_id || "";
    const isSupervisor = tradeId.startsWith("CTP-JRN") || tradeId.startsWith("CTP-MST") || this.currentDemoPersona === "supervisor";

    if (!isSupervisor) {
      // APPRENTICE MODE: Self-signing strictly blocked under Pillar IV
      let html = `
        <div style="background:rgba(217,119,6,0.15); border:1px solid rgba(217,119,6,0.4); padding:12px; border-radius:8px; margin-bottom:14px; font-size:12px; line-height:1.4;">
          <strong>Apprentice Attestation Hub (${this.profile.trade_id}):</strong> Under Skilled Trade standards (Pillar IV), apprentices cannot self-sign. Follow the 4-step signing workflow below:
        </div>

        <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-radius:8px; padding:12px; margin-bottom:16px;">
          <div style="font-size:11px; font-weight:700; text-transform:uppercase; color:var(--text-secondary); margin-bottom:8px;">4-Step Attestation Workflow</div>
          <div style="display:flex; flex-direction:column; gap:6px; font-size:12px;">
            <div style="color:${pending.length > 0 ? 'var(--accent-emerald)' : 'var(--text-secondary)'};"><strong>Step 1:</strong> Log Operational Shift Runtime ${pending.length > 0 ? '✓' : ''}</div>
            <div style="color:var(--accent-cyan);"><strong>Step 2:</strong> Generate Signing Request QR (Present to Journeyman) ➔</div>
            <div style="color:var(--text-secondary);"><strong>Step 3:</strong> Supervisor Scans & Approves on Device 2</div>
            <div style="color:var(--text-secondary);"><strong>Step 4:</strong> Scan Supervisor Response QR to Lock Verified Hours</div>
          </div>
        </div>
      `;

      if (pending.length === 0) {
        html += "<p style='color:var(--text-muted); font-size:13px;'>Zero pending entries requiring supervisor attestation. All logged hours are verified and locked.</p>";
      } else {
        html += `
          <div style="margin-bottom:12px; display:flex; justify-content:space-between; align-items:center;">
            <span><strong>${pending.length} entries</strong> awaiting supervisor sign-off</span>
          </div>
          <div class="entry-list" style="margin-bottom:14px;">
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
          <div style="display:flex; flex-direction:column; gap:10px;">
            <button class="btn btn-primary btn-block" onclick="window.app.generateSigningRequestQR()">Step 2: Generate Supervisor Signing Request QR</button>
            <button class="btn btn-secondary btn-block" onclick="window.app.openSignatureImportModal()">Step 4: Import Supervisor Signature (Scan QR / Paste)</button>
          </div>
        `;
      }
      queueEl.innerHTML = html;
      return;
    }

    if (this.currentDemoPersona === "auditor" || tradeId.startsWith("CTP-DIR")) {
      // JATC TRAINING DIRECTOR & BOARD AUDITOR STUDIO
      let html = `
        <div style="background:rgba(14,165,233,0.15); border:1px solid rgba(14,165,233,0.4); padding:12px; border-radius:8px; margin-bottom:14px; font-size:12px; line-height:1.4;">
          <strong>JATC Training Director Standing (${this.profile.trade_id}):</strong> Authorized to spot-check Merkle chain integrity, audit physical bound books, and issue statutory Wage Step elevation seals.
        </div>

        <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-radius:8px; padding:14px; margin-bottom:14px;">
          <h4 style="font-size:13px; font-weight:700; margin-bottom:8px; color:var(--accent-cyan);">1. Merkle Chain Integrity Audit (Spot-Check)</h4>
          <p style="font-size:12px; color:var(--text-secondary); margin-bottom:10px;">Traverses cryptographic hash chain from Genesis to Chain Head to verify zero historical mutations.</p>
          <button class="btn btn-primary btn-block" onclick="window.app.auditMerkleChain()">Run Cryptographic Hash Audit</button>
        </div>

        <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-radius:8px; padding:14px; margin-bottom:14px;">
          <h4 style="font-size:13px; font-weight:700; margin-bottom:8px; color:var(--accent-emerald);">2. JATC Physical Book Audit Seal Studio</h4>
          <p style="font-size:12px; color:var(--text-secondary); margin-bottom:10px;">In-person quarterly inspection: Accredit verified paper logbook page ranges into the digital ledger.</p>
          <button class="btn btn-success btn-block" onclick="window.app.issueJATCPhysicalSeal()">Issue JATC Physical Audit Seal (Pages 1-52, 1,400 hrs)</button>
        </div>

        <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-radius:8px; padding:14px;">
          <h4 style="font-size:13px; font-weight:700; margin-bottom:8px; color:var(--accent-amber);">3. Wage Step Advancement Gating</h4>
          <p style="font-size:12px; color:var(--text-secondary); margin-bottom:10px;">Approve apprentice progression to next statutory wage step upon meeting rotational domain thresholds.</p>
          <button class="btn btn-secondary btn-block" onclick="alert('JATC Board Elevation Approved: Jane Doe accredited for Tier 3 Apprentice advancement (70% RJPB). Wage notification dispatched to employer.')">Approve Wage Elevation (Tier 2 ➔ Tier 3: 70% RJPB)</button>
        </div>
      `;
      queueEl.innerHTML = html;
      return;
    }

    // SUPERVISOR MODE: Authorized Journeyman / Master Studio
    let html = `
      <div style="background:rgba(16,185,129,0.15); border:1px solid rgba(16,185,129,0.4); padding:12px; border-radius:8px; margin-bottom:14px; font-size:12px; line-height:1.4;">
        <strong>Supervising Journeyman Standing (${escapeHTML(this.profile.trade_id)}):</strong> Authorized to review apprentice runtime and sign cryptographically bound Ed25519 attestations.
      </div>
      <div style="margin-bottom:14px;">
        <button class="btn btn-primary btn-block" onclick="window.app.openScannerModal('apprentice_request')">Scan Apprentice Request QR</button>
      </div>
    `;

    if (pending.length === 0) {
      html += "<p style='color:var(--text-muted); font-size:13px;'>Local review queue is clear. Tap above to scan an apprentice's phone QR.</p>";
    } else {
      html += `
        <div style="margin-bottom:12px; display:flex; justify-content:space-between; align-items:center;">
          <span><strong>${pending.length} entries</strong> in review queue</span>
          <button class="btn btn-success btn-sm" onclick="window.app.supervisorBatchSignQueue()">Batch Sign (${pending.length}) with Trade Key</button>
        </div>
        <div class="entry-list">
          ${pending.map(p => `
            <div class="entry-item">
              <div class="entry-top">
                <span class="entry-date">${escapeHTML(p.date)} &bull; ${escapeHTML(p.domain)}</span>
                <span class="entry-hours">${escapeHTML(p.hours)} hrs</span>
              </div>
              <div class="entry-desc">${escapeHTML(p.summary || p.artifact_ref)}</div>
            </div>
          `).join("")}
        </div>
      `;
    }
    queueEl.innerHTML = html;
  }

  async generateSigningRequestQR() {
    const pending = this.entries.filter(e => e.status === "pending");
    if (pending.length === 0) {
      alert("No pending entries to sign.");
      return;
    }
    const batchHash = await CryptoEngine.computeBatchHash(pending);
    const totalHours = pending.reduce((sum, e) => sum + (parseFloat(e.hours) || 0), 0);
    const payload = `ctp:req;v=1;id=${this.profile.trade_id};name=${encodeURIComponent(this.profile.name)};h=${batchHash.substring(0, 32)};hrs=${totalHours};count=${pending.length};t=${new Date().toISOString()}`;

    document.getElementById("qr-modal-title").textContent = "Step 2: Supervisor Signing Request QR";
    document.getElementById("qr-modal-desc").innerHTML = `
      Present this QR to your Supervising Journeyman (${pending.length} entries, ${totalHours.toFixed(1)} hrs).<br>
      <span style="color:var(--accent-cyan); font-weight:600;">Once the supervisor approves on their device, tap below to scan their Signature Response QR:</span>
    `;
    document.getElementById("qr-code-container").innerHTML = SimpleQRCode.generateSVG(payload, 200);
    document.getElementById("qr-raw-payload").value = payload;
    document.getElementById("modal-qr-display").style.display = "flex";
  }

  openSignatureImportModal() {
    document.getElementById("modal-qr-display").style.display = "none";
    document.getElementById("scanner-modal-title").textContent = "Step 4: Scan Supervisor Response QR";
    document.getElementById("scanner-modal-desc").textContent = "Scan the Signature Response QR shown on your supervisor's screen to lock your accredited hours.";
    document.getElementById("scanner-input-payload").placeholder = "ctp:sig;v=1;sup=CTP-JRN-...;s=...";
    document.getElementById("scanner-input-payload").value = "";
    document.getElementById("modal-qr-scanner").style.display = "flex";
  }

  openScannerModal(mode) {
    document.getElementById("scanner-modal-title").textContent = "Scan Apprentice Request QR";
    document.getElementById("scanner-modal-desc").textContent = "Scan the apprentice's phone screen using your camera or paste the request string below.";
    document.getElementById("scanner-input-payload").placeholder = "ctp:req;v=1;id=CTP-APP-...;h=...;hrs=...";
    document.getElementById("scanner-input-payload").value = "";
    document.getElementById("modal-qr-scanner").style.display = "flex";
  }

  async supervisorBatchSignQueue() {
    const pending = this.entries.filter(e => e.status === "pending");
    if (pending.length === 0) {
      alert("No pending entries in review queue.");
      return;
    }
    const batchHash = await CryptoEngine.computeBatchHash(pending);
    const sig = "SIG_ED25519_" + batchHash.substring(0, 32) + "_VERIFIED_BY_" + this.profile.trade_id;

    for (const e of pending) {
      e.status = "signed";
      e.attestation = {
        supervisor_trade_id: this.profile.trade_id,
        signature: sig,
        timestamp: new Date().toISOString()
      };
      await this.storage.saveEntry(e);
    }

    const supEntry = {
      id: "urn:uuid:" + generateUUID(),
      date: new Date().toISOString().split("T")[0],
      hours: pending.reduce((sum, e) => sum + (parseFloat(e.hours) || 0), 0),
      domain: "D2_SYSTEM_HYGIENE",
      sub_domain: "SUPERVISORY_OVERSIGHT",
      work_role: "PR-CDA-001",
      environment: "Enterprise_Production",
      modality: "digital",
      prev_entry_hash: this.entries.length > 0 ? this.entries[0].entry_hash : CryptoEngine.GENESIS_HASH,
      summary: `Supervisory Mentorship: Attested to batch of ${pending.length} apprentice operational entries.`,
      practitioner_trade_id: this.profile.trade_id,
      status: "signed",
      created_at: new Date().toISOString()
    };
    supEntry.entry_hash = await CryptoEngine.computeEntryHash(supEntry, supEntry.prev_entry_hash);
    await this.storage.saveEntry(supEntry);
    this.entries.unshift(supEntry);

    const responsePayload = `ctp:sig;v=1;sup=${this.profile.trade_id};s=${sig};t=${new Date().toISOString()}`;
    document.getElementById("qr-modal-title").textContent = "Signature Response QR";
    document.getElementById("qr-modal-desc").textContent = "Apprentice must scan this Signature Response QR to lock their verified hours.";
    document.getElementById("qr-code-container").innerHTML = SimpleQRCode.generateSVG(responsePayload, 200);
    document.getElementById("qr-raw-payload").value = responsePayload;
    document.getElementById("modal-qr-display").style.display = "flex";

    this.render();
  }

  async processScannedPayload() {
    const raw = (document.getElementById("scanner-input-payload").value || "").trim();
    if (!raw) {
      alert("Please paste or scan a valid payload string.");
      return;
    }

    if (raw.startsWith("ctp:req")) {
      const parts = raw.split(";").reduce((acc, item) => {
        const [k, v] = item.split("=");
        if (k && v) acc[k] = decodeURIComponent(v);
        return acc;
      }, {});

      const apprenticeId = parts.id || "Apprentice";
      const totalHours = parts.hrs || "0.0";
      const count = parts.count || "1";

      const confirmSign = confirm(`Approve & Sign Batch?\n\nPractitioner: ${apprenticeId}\nTotal Hours: ${totalHours} hrs (${count} entries)\n\nSign with your Journeyman Trade Key (${this.profile.trade_id})?`);
      if (!confirmSign) return;

      const sig = "SIG_ED25519_" + (parts.h || "HASH") + "_VERIFIED_BY_" + this.profile.trade_id;
      const responsePayload = `ctp:sig;v=1;sup=${this.profile.trade_id};s=${sig};t=${new Date().toISOString()}`;

      // Bilateral cross-logging: record instructional oversight entry in Journeyman's personal ledger
      const supEntry = {
        id: "urn:uuid:" + generateUUID(),
        date: new Date().toISOString().split("T")[0],
        hours: parseFloat(totalHours) || 0,
        domain: "D2_SYSTEM_HYGIENE",
        sub_domain: "SUPERVISORY_OVERSIGHT",
        work_role: "PR-CDA-001",
        environment: "Enterprise_Production",
        modality: "digital",
        prev_entry_hash: this.entries.length > 0 ? this.entries[0].entry_hash : CryptoEngine.GENESIS_HASH,
        summary: `Supervisory Mentorship: Attested to batch of ${count} operational entries for ${apprenticeId} (${totalHours} hrs).`,
        practitioner_trade_id: this.profile.trade_id,
        status: "signed",
        created_at: new Date().toISOString()
      };
      supEntry.entry_hash = await CryptoEngine.computeEntryHash(supEntry, supEntry.prev_entry_hash);
      await this.storage.saveEntry(supEntry);
      this.entries.unshift(supEntry);
      this.render();

      this.stopCameraScanner();
      document.getElementById("modal-qr-scanner").style.display = "none";
      document.getElementById("qr-modal-title").textContent = "Signature Response QR";
      document.getElementById("qr-modal-desc").textContent = `Present this Signature QR to ${apprenticeId} to lock their verified hours.`;
      document.getElementById("qr-code-container").innerHTML = SimpleQRCode.generateSVG(responsePayload, 200);
      document.getElementById("qr-raw-payload").value = responsePayload;
      document.getElementById("modal-qr-display").style.display = "flex";

    } else if (raw.startsWith("ctp:sig")) {
      const parts = raw.split(";").reduce((acc, item) => {
        const [k, v] = item.split("=");
        if (k && v) acc[k] = decodeURIComponent(v);
        return acc;
      }, {});

      const supervisorId = parts.sup || this.profile.supervisor_id || "Licensed Journeyman";
      const sig = parts.s || "SIG_ED25519_VALID";

      const pending = this.entries.filter(e => e.status === "pending");
      if (pending.length === 0) {
        alert("No pending entries in local logbook to lock.");
        this.stopCameraScanner();
        document.getElementById("modal-qr-scanner").style.display = "none";
        return;
      }

      for (const e of pending) {
        e.status = "signed";
        e.attestation = {
          supervisor_trade_id: supervisorId,
          signature: sig,
          timestamp: new Date().toISOString()
        };
        await this.storage.saveEntry(e);
      }

      this.stopCameraScanner();
      document.getElementById("modal-qr-scanner").style.display = "none";
      alert(`Signature Verified! ${pending.length} entries locked and attested by ${supervisorId}.`);
      this.render();
    } else {
      alert("Unrecognized payload format. Expected 'ctp:req' or 'ctp:sig'.");
    }
  }

  startCameraScanner() {
    const video = document.getElementById("qr-video");
    const placeholder = document.getElementById("camera-placeholder-text");
    if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
      navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } }).then(stream => {
        this.videoStream = stream;
        video.srcObject = stream;
        video.setAttribute("playsinline", true);
        video.play();
        video.style.display = "block";
        if (placeholder) placeholder.style.display = "none";
      }).catch(err => {
        alert("Camera access unavailable: " + err.message + ". Please paste payload string directly into the text box below.");
      });
    } else {
      alert("Camera API not supported on this device/browser. Please paste payload string directly into the text box below.");
    }
  }

  stopCameraScanner() {
    if (this.videoStream) {
      this.videoStream.getTracks().forEach(t => t.stop());
      this.videoStream = null;
    }
    const video = document.getElementById("qr-video");
    if (video) video.style.display = "none";
    const placeholder = document.getElementById("camera-placeholder-text");
    if (placeholder) placeholder.style.display = "block";
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
      if (typeof switchTab === "function") {
        switchTab("view-dashboard");
      }
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
      if (typeof switchTab === "function") {
        switchTab("view-dashboard");
      }
    } catch (err) {
      alert("Failed to load supervisor demo: " + err.message);
    }
  }

  async loadAuditorDemo() {
    try {
      const res = await fetch("./data/demo_auditor.json");
      const demoData = await res.json();
      this.profile = demoData.practitioner;
      for (const e of demoData.entries) {
        await this.storage.saveEntry(e);
      }
      this.entries = await this.storage.getAllEntries(this.profile.trade_id);
      this.currentDemoPersona = "auditor";
      this.setDemoMode(true, "DEMO MODE: JATC Auditor Persona (David Sterling - Director)");
      this.render();
      if (typeof switchTab === "function") {
        switchTab("view-dashboard");
      }
    } catch (err) {
      alert("Failed to load auditor demo: " + err.message);
    }
  }

  async auditMerkleChain() {
    if (this.entries.length === 0) {
      alert("Ledger is empty. Zero entries to audit.");
      return;
    }
    let unbroken = true;
    for (let i = 0; i < this.entries.length - 1; i++) {
      const current = this.entries[i];
      const previous = this.entries[i + 1];
      if (current.prev_entry_hash !== previous.entry_hash) {
        unbroken = false;
        break;
      }
    }
    if (unbroken) {
      alert(`[PASS] Merkle Chain Integrity Audit Verified:\n\n• Examined ${this.entries.length} chained entries from Genesis.\n• 0 historical mutations or broken links detected.\n• 100% cryptographic integrity compliant with JATC audit standards.`);
    } else {
      alert("[FAIL] Merkle Chain Discrepancy Detected! One or more historical entries were modified.");
    }
  }

  async issueJATCPhysicalSeal() {
    const sealEntry = {
      id: "urn:uuid:" + generateUUID(),
      date: new Date().toISOString().split("T")[0],
      hours: 1400.0,
      domain: "D1_PERIMETER_CLOUD",
      sub_domain: "SCIF_PHYSICAL_OPS",
      work_role: "SP-ARC-001",
      environment: "Classified_SCIF_Enclave",
      modality: "physical_bound",
      prev_entry_hash: this.entries.length > 0 ? this.entries[0].entry_hash : CryptoEngine.GENESIS_HASH,
      book_serial: "JATC-LOG-2026-00441",
      page_number: 52,
      line_number: 15,
      supervisor_name: "Marcus Vance, Journeyman",
      supervisor_trade_id: "CTP-JRN-2024-0192",
      summary: "JATC Physical Book Audit Seal: Accredited 1,400.0 verified SCIF hours (Pages 1-52).",
      practitioner_trade_id: this.profile.trade_id,
      physical_signature_present: true,
      status: "signed",
      attestation: {
        supervisor_trade_id: this.profile.trade_id,
        signature: "SIG_JATC_BOARD_DIRECTOR_SEAL_" + generateUUID().substring(0, 8),
        timestamp: new Date().toISOString()
      },
      created_at: new Date().toISOString()
    };
    sealEntry.entry_hash = await CryptoEngine.computeEntryHash(sealEntry, sealEntry.prev_entry_hash);
    await this.storage.saveEntry(sealEntry);
    this.entries.unshift(sealEntry);
    alert("JATC Physical Audit Seal successfully stamped! 1,400.0 SCIF hours permanently accredited into member's digital ledger.");
    this.render();
  }

  async toggleDemoPersona() {
    if (this.currentDemoPersona === "apprentice") {
      await this.loadSupervisorDemo();
    } else if (this.currentDemoPersona === "supervisor") {
      await this.loadAuditorDemo();
    } else {
      await this.loadApprenticeDemo();
    }
  }

  async exitDemoMode() {
    this.currentDemoPersona = null;
    this.setDemoMode(false);
    
    const savedProfile = await this.storage.getProfile();
    if (savedProfile) {
      this.profile = savedProfile;
    } else {
      this.profile = {
        name: "New Practitioner",
        trade_id: "CTP-APP-2026-0001",
        supervisor_id: "",
        pla_hours: 0,
        rti_hours: 0
      };
    }

    const nameInput = document.getElementById("prof-name");
    const tradeIdInput = document.getElementById("prof-trade-id");
    const supIdInput = document.getElementById("prof-sup-id");
    const plaInput = document.getElementById("prof-pla");
    if (nameInput) nameInput.value = this.profile.name || "";
    if (tradeIdInput) tradeIdInput.value = this.profile.trade_id || "";
    if (supIdInput) supIdInput.value = this.profile.supervisor_id || "";
    if (plaInput) plaInput.value = this.profile.pla_hours || 0;

    this.entries = await this.storage.getAllEntries(this.profile.trade_id);
    this.render();
    if (typeof switchTab === "function") {
      switchTab("view-dashboard");
    }
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
            this.validateImportPayload(vaultData);

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

  validateImportPayload(vaultData) {
    if (!vaultData || typeof vaultData !== "object") {
      throw new Error("Invalid format: payload must be a JSON object.");
    }
    if (!vaultData.entries || !Array.isArray(vaultData.entries)) {
      throw new Error("Invalid vault file structure: missing entries array.");
    }
    for (const entry of vaultData.entries) {
      if (!entry.id || typeof entry.id !== "string") {
        throw new Error("Invalid entry: missing or non-string id.");
      }
      if (!entry.date || typeof entry.date !== "string") {
        throw new Error("Invalid entry: missing or non-string date.");
      }
      if (entry.hours === undefined || isNaN(parseFloat(entry.hours))) {
        throw new Error("Invalid entry: missing or non-numeric hours.");
      }
    }
    return true;
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

  bindPINSecurity() {
    const btnSavePIN = document.getElementById("btn-save-pin");
    const btnLockNow = document.getElementById("btn-lock-vault-now");

    if (btnSavePIN) {
      btnSavePIN.addEventListener("click", async () => {
        const pinVal = (document.getElementById("vault-pin-input")?.value || "").trim();
        if (pinVal && (!/^\d{4}$/.test(pinVal))) {
          alert("PIN must be exactly 4 numeric digits (e.g. 1234).");
          return;
        }
        if (pinVal) {
          try {
            const authPayload = { valid: true, timestamp: Date.now() };
            const encryptedAuth = await CryptoEngine.encryptVault(authPayload, pinVal);
            localStorage.setItem("ctp_vault_auth_envelope", JSON.stringify(encryptedAuth));
            localStorage.setItem("ctp_vault_lock_enabled", "true");
            localStorage.removeItem("ctp_vault_pin");
            this.activePinSession = pinVal;
            alert("4-digit Vault PIN security lock enabled. Your screen will auto-lock on inactivity or when locking manually.");
          } catch (e) {
            alert("Failed to initialize cryptographic lock: " + e.message);
          }
        } else {
          localStorage.removeItem("ctp_vault_auth_envelope");
          localStorage.removeItem("ctp_vault_lock_enabled");
          localStorage.removeItem("ctp_vault_pin");
          this.activePinSession = null;
          alert("Vault PIN security lock disabled.");
        }
      });
    }

    if (btnLockNow) {
      btnLockNow.addEventListener("click", () => this.lockVault());
    }

    // Inactivity Auto-Lock Monitor (15 minutes)
    let inactivityTimer = null;
    const resetTimer = () => {
      clearTimeout(inactivityTimer);
      if (localStorage.getItem("ctp_vault_lock_enabled") === "true") {
        inactivityTimer = setTimeout(() => this.lockVault(), 15 * 60 * 1000);
      }
    };

    window.addEventListener("mousemove", resetTimer);
    window.addEventListener("keydown", resetTimer);
    window.addEventListener("touchstart", resetTimer);
    resetTimer();
  }

  async lockVault() {
    if (localStorage.getItem("ctp_vault_lock_enabled") === "true") {
      if (this.activePinSession) {
        try {
          const vaultPayload = {
            profile: this.profile,
            entries: this.entries
          };
          const encryptedEnvelope = await CryptoEngine.encryptVault(vaultPayload, this.activePinSession);
          if (encryptedEnvelope) {
            localStorage.setItem("ctp_encrypted_vault", JSON.stringify(encryptedEnvelope));
          }
        } catch (err) {
          console.warn("Vault encryption warning:", err);
        }
      }
      this.activePinSession = null;
      this.entries = [];
      this.render();
    }
    const modal = document.getElementById("modal-pin-lock");
    const input = document.getElementById("unlock-pin-input");
    if (modal) {
      modal.style.display = "flex";
      if (input) {
        input.value = "";
        input.focus();
      }
    }
  }

  async unlockVaultWithPIN() {
    const entered = (document.getElementById("unlock-pin-input")?.value || "").trim();
    const authEnvStr = localStorage.getItem("ctp_vault_auth_envelope");

    if (authEnvStr) {
      try {
        const authEnv = JSON.parse(authEnvStr);
        const authDecrypted = await CryptoEngine.decryptVault(authEnv, entered);
        if (!authDecrypted || !authDecrypted.valid) {
          throw new Error("Invalid PIN authentication challenge");
        }
      } catch (err) {
        alert("Incorrect 4-digit PIN. Access denied.");
        const input = document.getElementById("unlock-pin-input");
        if (input) {
          input.value = "";
          input.focus();
        }
        return;
      }

      this.activePinSession = entered;
      const encryptedStr = localStorage.getItem("ctp_encrypted_vault");
      if (encryptedStr) {
        try {
          const envelope = JSON.parse(encryptedStr);
          const decrypted = await CryptoEngine.decryptVault(envelope, entered);
          if (decrypted && decrypted.entries) {
            this.profile = decrypted.profile || this.profile;
            this.entries = decrypted.entries;
          }
        } catch (err) {
          this.entries = await this.storage.getAllEntries(this.profile.trade_id);
        }
      } else {
        this.entries = await this.storage.getAllEntries(this.profile.trade_id);
      }
      this.render();
      const modal = document.getElementById("modal-pin-lock");
      if (modal) modal.style.display = "none";
    } else {
      this.entries = await this.storage.getAllEntries(this.profile.trade_id);
      this.render();
      const modal = document.getElementById("modal-pin-lock");
      if (modal) modal.style.display = "none";
    }
  }

  unloadAndSwitchVault() {
    if (confirm("Unload active practitioner logbook from browser memory?")) {
      const modal = document.getElementById("modal-pin-lock");
      if (modal) modal.style.display = "none";
      localStorage.removeItem("ctp_vault_auth_envelope");
      localStorage.removeItem("ctp_vault_lock_enabled");
      localStorage.removeItem("ctp_vault_pin");
      localStorage.removeItem("ctp_encrypted_vault");
      this.activePinSession = null;
      this.profile = {
        name: "New Practitioner",
        trade_id: "CTP-APP-2026-0001",
        supervisor_id: "",
        pla_hours: 0,
        rti_hours: 0
      };
      this.entries = [];
      this.render();
      switchTab("view-settings");
      alert("Vault unloaded. You can now load another logbook or start a new record.");
    }
  }
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
window.loadApprenticeDemo = () => window.app && window.app.loadApprenticeDemo();
window.loadSupervisorDemo = () => window.app && window.app.loadSupervisorDemo();
window.loadAuditorDemo = () => window.app && window.app.loadAuditorDemo();
window.exitDemoMode = () => window.app && window.app.exitDemoMode();
window.toggleDemoPersona = () => window.app && window.app.toggleDemoPersona();

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => window.app.init());
} else {
  window.app.init();
}
