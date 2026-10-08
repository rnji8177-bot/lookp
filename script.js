// ==========================================================================
// OSINT LOOKUP PRO (v3.0) - CLIENT CONTROLLER & TELEMETRY
// ==========================================================================

let currentUserData = null;
let selectedPlan = "1day";
let selectedAmount = 20;
let currentLookupData = null;
let currentScannedNumber = "";
let verificationInterval = null;

// Initialize on DOM Ready
document.addEventListener("DOMContentLoaded", () => {
  initUser();
  loadSearchHistory();
});

// 1. Device Fingerprinting Helper (Defense-in-depth against multi-account spam)
let cachedFingerprint = "";

async function generateDeviceFingerprint() {
  if (cachedFingerprint) return cachedFingerprint;

  let components = [];
  try {
    components.push(`${screen.width}x${screen.height}x${screen.colorDepth}`);
    components.push(`dpr:${window.devicePixelRatio || 1}`);
    components.push(`cores:${navigator.hardwareConcurrency || 4}`);
    components.push(`plat:${navigator.platform || ""}`);
    components.push(`tz:${Intl.DateTimeFormat().resolvedOptions().timeZone || ""}`);
    components.push(`lang:${navigator.language || ""}`);

    // Canvas GPU Render test
    const canvas = document.createElement("canvas");
    canvas.width = 240;
    canvas.height = 60;
    const ctx = canvas.getContext("2d");
    if (ctx) {
      ctx.textBaseline = "top";
      ctx.font = "14px 'Arial'";
      ctx.fillStyle = "#f60";
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = "#069";
      ctx.fillText("OSINT_PRO_🔒_#891", 2, 15);
      components.push("canv:" + canvas.toDataURL().slice(-60));
    }
  } catch (err) {
    components.push("fallback:" + navigator.userAgent);
  }

  // Fast hashing
  let str = components.join("|||");
  let hash1 = 0x811c9dc5;
  let hash2 = 0x55555555;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    hash1 = (hash1 ^ ch) * 0x01000193;
    hash2 = (hash2 ^ (ch << (i % 8))) * 0x5bd1e995;
  }
  cachedFingerprint = "fp_" + Math.abs(hash1).toString(16) + Math.abs(hash2).toString(16);
  return cachedFingerprint;
}

// XSS Sanitizer Helper (Crucial for defensive security)
function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

async function initUser() {
  await generateDeviceFingerprint();
  refreshUserStatus();
}

async function refreshUserStatus(showToastOnCheck = false) {
  try {
    const fp = await generateDeviceFingerprint();
    const res = await fetch(`/api/user-status?fp=${encodeURIComponent(fp)}`, {
      headers: { "X-Device-Fingerprint": fp }
    });
    
    if (res.status === 401) {
      // User session expired or not authenticated -> redirect to login
      window.location.href = "/login";
      return;
    }

    if (!res.ok) return;
    const data = await res.json();
    currentUserData = data;
    updateQuotaUI(data);

    // If user was waiting for verification and now got approved
    if (data.is_premium) {
      if (verificationInterval) {
        clearInterval(verificationInterval);
        verificationInterval = null;
      }
      const verifyingSec = document.getElementById("verifyingSection");
      const formSec = document.getElementById("paymentFormSection");
      if (verifyingSec && verifyingSec.style.display !== "none") {
        verifyingSec.style.display = "none";
        if (formSec) formSec.style.display = "block";
        closePricingModal();
        showToast("🎉 Mubarak! Aapka Pro Plan Activate Ho Gaya Hai!");
      }
    } else if (data.pending_payment) {
      showPendingVerificationUI(data.pending_payment);
      if (!verificationInterval) {
        verificationInterval = setInterval(() => refreshUserStatus(false), 6000);
      }
    }

    if (showToastOnCheck) {
      if (data.is_premium) {
        showToast("✅ Plan Active: " + (data.expires_in_human || "Unlimited"));
      } else if (data.pending_payment) {
        showToast("⏳ Status: Still verifying with Admin. Please wait...");
      } else {
        showToast(`Free Searches: ${data.free_lookups_left} of 3 remaining`);
      }
    }
  } catch (err) {
    console.error("User status check failed:", err);
  }
}

function updateQuotaUI(user) {
  const badge = document.getElementById("quotaBadge");
  const icon = document.getElementById("quotaIcon");
  const text = document.getElementById("quotaText");
  const upgradeBtn = document.getElementById("upgradeBtn");
  const quotaBanner = document.getElementById("quotaExhaustedBanner");

  if (!badge) return;

  badge.className = "quota-badge"; // reset

  if (user.is_premium) {
    badge.classList.add("premium");
    icon.textContent = "👑";
    text.textContent = `PRO: ${user.expires_in_human || "Active"}`;
    if (upgradeBtn) upgradeBtn.style.display = "none";
    if (quotaBanner) quotaBanner.style.display = "none";
  } else {
    if (user.free_lookups_left <= 0) {
      badge.classList.add("exhausted");
      icon.textContent = "⚠️";
      text.textContent = "0/3 Free Left";
      if (quotaBanner) quotaBanner.style.display = "flex";
    } else {
      badge.classList.add("free");
      icon.textContent = "⚡";
      text.textContent = `${user.free_lookups_left}/3 Free`;
      if (quotaBanner) quotaBanner.style.display = "none";
    }
    if (upgradeBtn) upgradeBtn.style.display = "flex";
  }
}

// 2. Search Input Controls
function handleInput(input) {
  input.value = input.value.replace(/\D/g, "");
  const count = input.value.length;
  document.getElementById("charCount").textContent = count;
  document.getElementById("clearInputBtn").style.display = count > 0 ? "block" : "none";
}

function clearInput() {
  const input = document.getElementById("phoneInput");
  input.value = "";
  handleInput(input);
  input.focus();
}

function fillSample(num) {
  const input = document.getElementById("phoneInput");
  input.value = num;
  handleInput(input);
  startLookup();
}

// 3. Lookup Engine Execution
async function startLookup() {
  const input = document.getElementById("phoneInput");
  const number = input.value.trim();

  if (number.length !== 10) {
    showToast("⚠️ Kripya valid 10-digit mobile number enter karein");
    input.focus();
    return;
  }

  // Pre-check free limit
  if (currentUserData && !currentUserData.is_premium && currentUserData.free_lookups_left <= 0) {
    openPricingModal("Aapki 3 Free Searches limit khatam ho chuki hai. Aage lookup ke liye plan choose karein.");
    return;
  }

  // UI State: Scanning
  showScanningState(true);
  hideResults();
  hideError();

  currentScannedNumber = number;

  try {
    const fp = await generateDeviceFingerprint();
    const res = await fetch(`/lookup?number=${encodeURIComponent(number)}&fp=${encodeURIComponent(fp)}`, {
      headers: { "X-Device-Fingerprint": fp }
    });
    
    if (res.status === 401) {
      showScanningState(false);
      showToast("🔒 Session expired. Kripya login karein.");
      setTimeout(() => { window.location.href = "/login"; }, 1000);
      return;
    }

    const data = await res.json();
    showScanningState(false);

    if (res.status === 403 || data.require_plan) {
      openPricingModal(data.message || "Aapki 3 Free Searches limit poori ho gayi hai.");
      refreshUserStatus();
      return;
    }

    if (!res.ok || data.error) {
      showError(data.error, data.message || "Lookup request complete nahi ho payi.");
      return;
    }

    // Success
    currentLookupData = data.data;
    renderResults(number, data.data);
    saveSearchHistory(number);
    refreshUserStatus();

  } catch (err) {
    showScanningState(false);
    showError("CONNECTION_ERROR", "Server response time out ho gaya ya connection fail hua. Dobara koshish karein.");
  }
}

// Scanning Radar & Terminal Animation
let terminalTimer = null;
function showScanningState(show) {
  const sec = document.getElementById("scanningState");
  const scanBtn = document.getElementById("scanBtn");

  if (show) {
    sec.style.display = "flex";
    scanBtn.disabled = true;
    scanBtn.style.opacity = "0.6";

    const steps = [
      "> [1/3] Establishing TLS 1.3 tunnel with national telecom routing nodes...",
      "> [2/3] Querying central HLR subscriber registers & operator circles...",
      "> [3/3] Cross-referencing address records & linked identities...",
      "> [✓] Parsing verified telecom payloads..."
    ];
    let stepIdx = 0;
    const term = document.getElementById("terminalStep");
    term.textContent = steps[0];

    terminalTimer = setInterval(() => {
      stepIdx++;
      if (stepIdx < steps.length) {
        term.textContent = steps[stepIdx];
      }
    }, 1800);

  } else {
    sec.style.display = "none";
    scanBtn.disabled = false;
    scanBtn.style.opacity = "1";
    if (terminalTimer) clearInterval(terminalTimer);
  }
}

function hideResults() {
  document.getElementById("resultsSection").style.display = "none";
  const rawBox = document.getElementById("rawJsonBox");
  if (rawBox) rawBox.style.display = "none";
}

function hideError() {
  document.getElementById("errorBanner").style.display = "none";
}

function showError(title, msg) {
  const banner = document.getElementById("errorBanner");
  document.getElementById("errorTitle").textContent = title || "Notice";
  document.getElementById("errorMessage").textContent = msg;
  banner.style.display = "flex";
}

// 4. Universal OSINT Normalizer & Structured Card Renderer (With XSS Sanitization)
function toTitleCase(str) {
  if (!str || typeof str !== "string") return "N/A";
  return str.toLowerCase().split(' ').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
}

function extractOsintRecord(raw) {
  let mainRecord = null;
  let altRecords = [];

  if (!raw) return { record: {}, altRecords: [] };

  if (raw.data && raw.data.Data && Array.isArray(raw.data.Data.Main_Records) && raw.data.Data.Main_Records.length > 0) {
    mainRecord = raw.data.Data.Main_Records[0];
    if (Array.isArray(raw.data.Data.Alt_Records)) {
      altRecords = raw.data.Data.Alt_Records;
    }
  } else if (raw.Data && Array.isArray(raw.Data.Main_Records) && raw.Data.Main_Records.length > 0) {
    mainRecord = raw.Data.Main_Records[0];
    if (Array.isArray(raw.Data.Alt_Records)) {
      altRecords = raw.Data.Alt_Records;
    }
  } else if (raw.Main_Records && Array.isArray(raw.Main_Records) && raw.Main_Records.length > 0) {
    mainRecord = raw.Main_Records[0];
    if (Array.isArray(raw.Alt_Records)) {
      altRecords = raw.Alt_Records;
    }
  } else if (Array.isArray(raw) && raw.length > 0) {
    mainRecord = raw[0];
    altRecords = raw.slice(1);
  } else if (raw.data && typeof raw.data === "object") {
    if (Array.isArray(raw.data) && raw.data.length > 0) {
      mainRecord = raw.data[0];
      altRecords = raw.data.slice(1);
    } else if (raw.data.records && Array.isArray(raw.data.records) && raw.data.records.length > 0) {
      mainRecord = raw.data.records[0];
      altRecords = raw.data.records.slice(1);
    } else {
      mainRecord = raw.data;
    }
  } else if (typeof raw === "object") {
    mainRecord = raw;
  }

  return {
    record: mainRecord || {},
    altRecords: altRecords || []
  };
}

function renderResults(phoneNumber, raw) {
  const container = document.getElementById("cardsGrid");
  container.innerHTML = "";

  document.getElementById("scannedNumberDisplay").textContent = `+91 ${escapeHtml(phoneNumber.slice(0, 5))} ${escapeHtml(phoneNumber.slice(5))}`;
  document.getElementById("scannedMeta").textContent = "Telecom Record Verified • Active Node";

  const rawPre = document.getElementById("rawJsonContent");
  if (rawPre) {
    rawPre.textContent = JSON.stringify(raw, null, 2);
  }

  const { record, altRecords } = extractOsintRecord(raw);

  // Identity Fields
  const rawName = record.name || record.NAME || record.fullName || record.user_name || record.FullName || "";
  const name = rawName ? toTitleCase(rawName) : "N/A";

  const rawFather = record.fname || record.FNAME || record.father_name || record.fatherName || record.guardian || record.Father_Name || "";
  const fatherName = rawFather ? toTitleCase(rawFather) : "N/A";

  const refId = record.id || record.aadhaar_ref || record.ref_id || "";

  // Address
  let rawAddr = record.address || record.ADDRESS || record.full_address || record.Address || "";
  let cleanAddr = rawAddr ? rawAddr.replace(/!+/g, ", ").replace(/,\s*,/g, ",").trim().replace(/^,\s*/, "").replace(/,\s*$/, "") : "";
  if (!cleanAddr) {
    cleanAddr = [record.city, record.district, record.state, record.pincode].filter(Boolean).join(", ");
  }
  if (!cleanAddr) cleanAddr = "Location details unavailable";

  let pincode = record.pincode || record.PINCODE || record.pin || record.postal_code || "";
  if (!pincode && cleanAddr) {
    const pinMatch = cleanAddr.match(/\b\d{6}\b/);
    if (pinMatch) pincode = pinMatch[0];
  }

  // Carrier & Circle
  const circleRaw = record.circle || record.CIRCLE || record.state || record.STATE || record.Circle || "India";
  let carrier = record.carrier || record.CARRIER || record.operator || record.OPERATOR || "";
  if (!carrier && circleRaw) {
    const up = String(circleRaw).toUpperCase();
    if (up.includes("JIO")) carrier = "Reliance Jio Infocomm";
    else if (up.includes("AIRTEL")) carrier = "Bharti Airtel";
    else if (up.includes("VI") || up.includes("VODAFONE") || up.includes("IDEA")) carrier = "Vodafone Idea (Vi)";
    else if (up.includes("BSNL")) carrier = "BSNL Mobile";
    else carrier = "Telecom Carrier";
  }

  // Alternate Numbers
  const allLinkedNumbers = new Set();
  if (record.alt) {
    const digits = String(record.alt).replace(/\D/g, "");
    if (digits.length >= 10 && digits !== phoneNumber) allLinkedNumbers.add(digits.slice(-10));
  }
  if (Array.isArray(record.alternate_numbers)) {
    record.alternate_numbers.forEach(n => {
      const digits = String(n).replace(/\D/g, "");
      if (digits.length >= 10 && digits !== phoneNumber) allLinkedNumbers.add(digits.slice(-10));
    });
  }
  altRecords.forEach(ar => {
    if (ar.mobile) {
      const digits = String(ar.mobile).replace(/\D/g, "");
      if (digits.length >= 10 && digits !== phoneNumber) allLinkedNumbers.add(digits.slice(-10));
    }
    if (ar.alt) {
      const digits = String(ar.alt).replace(/\D/g, "");
      if (digits.length >= 10 && digits !== phoneNumber) allLinkedNumbers.add(digits.slice(-10));
    }
  });

  // Card 1: Identity Profile
  const idCard = document.createElement("div");
  idCard.className = "data-card glass-panel";
  idCard.innerHTML = `
    <div class="card-header">
      <span class="card-icon">🪪</span>
      <span class="card-title">Identity Profile</span>
    </div>
    <div class="card-body">
      <div class="field-row">
        <span class="field-label">Full Name</span>
        <span class="field-value highlight">${escapeHtml(name)}</span>
      </div>
      <div class="field-row">
        <span class="field-label">Father / Guardian</span>
        <span class="field-value">${escapeHtml(fatherName)}</span>
      </div>
      ${refId ? `
      <div class="field-row">
        <span class="field-label">Registry Node Ref ID</span>
        <span class="field-value" style="font-family:'JetBrains Mono'; font-size:13px; color:var(--text-dim);">${escapeHtml(refId)}</span>
      </div>` : ''}
      <div class="field-row">
        <span class="field-label">Verification Status</span>
        <span class="field-value" style="color:var(--accent-cyan);">● Government Telephony Linked</span>
      </div>
    </div>
  `;
  container.appendChild(idCard);

  // Card 2: Registered Location
  const locCard = document.createElement("div");
  locCard.className = "data-card glass-panel";
  locCard.innerHTML = `
    <div class="card-header">
      <span class="card-icon">📍</span>
      <span class="card-title">Registered Address</span>
    </div>
    <div class="card-body">
      <div class="field-row">
        <span class="field-label">Address</span>
        <span class="field-value">${escapeHtml(cleanAddr)}</span>
      </div>
      ${pincode ? `
      <div class="field-row">
        <span class="field-label">Postal PIN Code</span>
        <span class="field-value" style="font-family:'JetBrains Mono'; color:var(--accent-gold);">${escapeHtml(pincode)}</span>
      </div>` : ''}
      <a href="https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(cleanAddr)}" target="_blank" rel="noopener noreferrer" class="btn-map-link">
        <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path><circle cx="12" cy="10" r="3"></circle></svg>
        <span>Open in Google Maps</span>
      </a>
    </div>
  `;
  container.appendChild(locCard);

  // Card 3: Telecom & Network Carrier
  const carrierCard = document.createElement("div");
  carrierCard.className = "data-card glass-panel";
  carrierCard.innerHTML = `
    <div class="card-header">
      <span class="card-icon">📡</span>
      <span class="card-title">Telecom Routing</span>
    </div>
    <div class="card-body">
      <div class="field-row">
        <span class="field-label">Carrier Provider</span>
        <span class="field-value" style="color:var(--accent-blue);">${escapeHtml(carrier)}</span>
      </div>
      <div class="field-row">
        <span class="field-label">Telecom Circle / Zone</span>
        <span class="field-value">${escapeHtml(circleRaw)}</span>
      </div>
      <div class="field-row">
        <span class="field-label">Network Type</span>
        <span class="field-value">GSM / 4G VoLTE / 5G SA</span>
      </div>
    </div>
  `;
  container.appendChild(carrierCard);

  // Card 4: Linked & Alternate Numbers
  if (allLinkedNumbers.size > 0) {
    const altCard = document.createElement("div");
    altCard.className = "data-card glass-panel";
    let chipsHtml = Array.from(allLinkedNumbers).map(num => `
      <span class="clickable-chip" onclick="fillSample('${escapeHtml(num)}')" title="Click to scan this number">
        📞 +91 ${escapeHtml(num)}
      </span>
    `).join("");

    altCard.innerHTML = `
      <div class="card-header">
        <span class="card-icon">🔗</span>
        <span class="card-title">Linked Contacts (${allLinkedNumbers.size})</span>
      </div>
      <div class="card-body">
        <span class="field-label">Associated Mobile Numbers (Click to Scan):</span>
        <div class="chip-container">${chipsHtml}</div>
      </div>
    `;
    container.appendChild(altCard);
  }

  // Card 5: Alternate Registered SIMs
  if (altRecords && altRecords.length > 0) {
    const multiSimCard = document.createElement("div");
    multiSimCard.className = "data-card glass-panel";
    multiSimCard.style.gridColumn = "1 / -1";

    let altRows = altRecords.map((ar) => {
      const arNum = ar.mobile || "N/A";
      const arAddr = ar.address ? ar.address.replace(/!+/g, ", ").trim() : "Same identity address";
      const arCircle = ar.circle || "Telecom Node";
      const safeClean = String(arNum).replace(/\D/g, "");
      return `
        <div style="background:rgba(255,255,255,0.03); border:1px solid var(--border-subtle); padding:12px; border-radius:8px; margin-top:8px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
          <div>
            <div style="font-weight:700; color:#fff; font-family:'JetBrains Mono';">+91 ${escapeHtml(arNum)}</div>
            <div style="font-size:12px; color:var(--text-muted); margin-top:3px;">${escapeHtml(arAddr)}</div>
            <div style="font-size:11px; color:var(--accent-cyan);">${escapeHtml(arCircle)}</div>
          </div>
          <button class="clickable-chip" onclick="fillSample('${escapeHtml(safeClean)}')" style="margin:0;">
            Scan This SIM ➔
          </button>
        </div>
      `;
    }).join("");

    multiSimCard.innerHTML = `
      <div class="card-header">
        <span class="card-icon">📱</span>
        <span class="card-title">Additional SIMs Under Same Identity (${altRecords.length})</span>
      </div>
      <div class="card-body">
        <span class="field-label">Other registered lines detected for this subscriber:</span>
        <div>${altRows}</div>
      </div>
    `;
    container.appendChild(multiSimCard);
  }

  // Show Section
  document.getElementById("resultsSection").style.display = "block";
  document.getElementById("resultsSection").scrollIntoView({ behavior: "smooth" });
}

function toggleRawView() {
  const box = document.getElementById("rawJsonBox");
  if (!box) return;
  box.style.display = box.style.display === "none" ? "block" : "none";
  if (box.style.display === "block") {
    box.scrollIntoView({ behavior: "smooth" });
  }
}

// 5. Pricing & Paywall Modal Controls
function openPricingModal(customSubText = "") {
  if (customSubText) {
    document.getElementById("pricingSub").textContent = customSubText;
  }
  document.getElementById("pricingModal").style.display = "flex";
  selectPlan("1day", 20);
}

function closePricingModal() {
  document.getElementById("pricingModal").style.display = "none";
}

function selectPlan(plan, amount) {
  selectedPlan = plan;
  selectedAmount = amount;

  const card1 = document.getElementById("plan1Card");
  const card7 = document.getElementById("plan7Card");
  const r1 = document.getElementById("radio1day");
  const r7 = document.getElementById("radio7days");

  if (plan === "1day") {
    card1.classList.add("active");
    card7.classList.remove("active");
    r1.checked = true;
    r7.checked = false;
  } else {
    card7.classList.add("active");
    card1.classList.remove("active");
    r7.checked = true;
    r1.checked = false;
  }

  // Update Direct UPI Link
  const upiId = document.getElementById("upiIdText").textContent.trim();
  const directBtn = document.getElementById("directUpiBtn");
  const note = plan === "1day" ? "LookupDailyPass" : "LookupWeeklyPass";
  directBtn.href = `upi://pay?pa=${encodeURIComponent(upiId)}&pn=SANDESH%20KUMAR%20MADDHESHIA&am=${amount}&cu=INR&tn=${note}`;
  directBtn.querySelector("span").textContent = `⚡ Pay ₹${amount} via UPI App`;
}

function copyUPI() {
  const upiId = document.getElementById("upiIdText").textContent.trim();
  navigator.clipboard.writeText(upiId).then(() => {
    showToast("📋 UPI ID Copied: " + upiId);
  }).catch(() => {
    showToast("UPI ID: " + upiId);
  });
}

// 6. Submit Payment Details ("I Have Paid")
async function submitPaymentDetails() {
  const utrInput = document.getElementById("utrInput");
  const utr = utrInput.value.trim();

  if (utr.length < 6) {
    showToast("⚠️ Kripya valid 12-digit UTR ya UPI Ref ID enter karein");
    utrInput.focus();
    return;
  }

  const btn = document.getElementById("submitPayBtn");
  btn.disabled = true;
  btn.textContent = "Submitting...";

  try {
    const res = await fetch("/api/submit-payment", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        plan_type: selectedPlan,
        utr: utr,
        user_note: ""
      })
    });

    const data = await res.json();
    btn.disabled = false;
    btn.textContent = "Submit for Approval";

    if (res.ok && data.success) {
      showToast("✅ Payment details submitted to Admin!");
      showPendingVerificationUI(data.request);

      if (!verificationInterval) {
        verificationInterval = setInterval(() => refreshUserStatus(false), 6000);
      }
    } else {
      showToast("⚠️ " + (data.error || "Submission failed"));
    }
  } catch (err) {
    btn.disabled = false;
    btn.textContent = "Submit for Approval";
    showToast("⚠️ Error submitting: " + err.message);
  }
}

function showPendingVerificationUI(req) {
  const formSec = document.getElementById("paymentFormSection");
  const verifyingSec = document.getElementById("verifyingSection");

  if (formSec) formSec.style.display = "none";
  if (verifyingSec) {
    verifyingSec.style.display = "flex";
    document.getElementById("submittedUtrDisplay").textContent = req.utr || "Submitted";
  }
}

// 7. Report Export & Copy Tools
function copyFullReport() {
  if (!currentLookupData) return;
  const text = JSON.stringify(currentLookupData, null, 2);
  navigator.clipboard.writeText(text).then(() => {
    showToast("📋 Full OSINT Report Copied to Clipboard!");
  });
}

function downloadReport() {
  if (!currentLookupData) return;
  const text = JSON.stringify(currentLookupData, null, 2);
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `OSINT_REPORT_${currentScannedNumber || "DATA"}.txt`;
  a.click();
  showToast("📥 Report Downloaded!");
}

// 8. History Drawer Controls
function toggleHistoryDrawer() {
  const drawer = document.getElementById("historyDrawer");
  drawer.style.display = drawer.style.display === "none" ? "flex" : "none";
}

function saveSearchHistory(number) {
  let hist = JSON.parse(localStorage.getItem("osint_history") || "[]");
  hist = hist.filter(item => item.number !== number);
  hist.unshift({ number, time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) });
  if (hist.length > 20) hist.pop();
  localStorage.setItem("osint_history", JSON.stringify(hist));
  loadSearchHistory();
}

function loadSearchHistory() {
  const list = document.getElementById("historyList");
  if (!list) return;
  const hist = JSON.parse(localStorage.getItem("osint_history") || "[]");

  if (hist.length === 0) {
    list.innerHTML = `<div style="color:var(--text-dim); text-align:center; padding:30px 10px; font-size:13px;">No recent searches yet.</div>`;
    return;
  }

  list.innerHTML = hist.map(item => `
    <div class="history-item" onclick="fillSample('${escapeHtml(item.number)}'); toggleHistoryDrawer();">
      <span class="history-number">+91 ${escapeHtml(item.number)}</span>
      <span class="history-time">${escapeHtml(item.time)}</span>
    </div>
  `).join("");
}

function clearSearchHistory() {
  localStorage.removeItem("osint_history");
  loadSearchHistory();
  showToast("History cleared");
}

// 9. Toast Notification System
function showToast(msg) {
  const toast = document.getElementById("toast");
  if (!toast) return;
  toast.textContent = msg;
  toast.classList.add("show");
  setTimeout(() => {
    toast.classList.remove("show");
  }, 3500);
}
