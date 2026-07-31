/***********************
 * Utilities
 ***********************/
const state = {
  auth: {
    mode: 'create',
    remembered: false,
    user: null
  },
  chat: {
    activeMode: 'url',
    uploadedImage: null,
    uploadedImagePreviewUrl: null
  },
  analysis: {
    lastInput: null,
    lastResult: null
  }
};
// ==============================
// Backend API Configuration
// ==============================

const API_BASE = "https://cybershield-production-64c0.up.railway.app/api/users";
const $ = (id) => document.getElementById(id);

function showToast(message) {
  const t = $('globalToast');
  t.textContent = message;
  t.classList.remove('hidden');
  clearTimeout(showToast._timer);
  showToast._timer = setTimeout(() => t.classList.add('hidden'), 2200);
}

function showScreen(id) {

  ['screen1', 'screen2', 'screen3', 'screen4'].forEach((s) => {

    const screen = $(s);

    if (screen) {
      screen.classList.add('hidden');
    }

  });

  const current = $(id);

  if (current) {
    current.classList.remove('hidden');
  }

}

function setAuthTab(mode) {
  state.auth.mode = mode;
  const isSignIn = mode === 'signin';
  $('tabSignIn').className =
    'auth-tab px-4 py-2 rounded-t-xl border border-border border-b-0 ' +
    (isSignIn ? 'bg-surface-2 text-text' : 'bg-surface text-text-dim') +
    ' hover:text-text hover:bg-surface-2 transition';
  $('tabCreate').className =
    'auth-tab px-4 py-2 rounded-t-xl border border-border border-b-0 ' +
    (!isSignIn ? 'bg-surface-2 text-text' : 'bg-surface text-text-dim') +
    ' hover:text-text hover:bg-surface-2 transition';

  $('fullNameWrap').classList.toggle('hidden', isSignIn);
  $('pwStrengthWrap').classList.toggle('hidden', isSignIn);
}

function setError(id, msg) {
  const el = $(id);
  if (!el) return;
  if (!msg) {
    el.textContent = '';
    el.classList.add('hidden');
  } else {
    el.textContent = msg;
    el.classList.remove('hidden');
  }
}

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email).trim());
}

function passwordStrength(pw) {
  const s = String(pw);
  let score = 0;
  if (s.length >= 8) score += 30;
  if (s.length >= 12) score += 20;
  if (/[A-Z]/.test(s)) score += 15;
  if (/[a-z]/.test(s)) score += 10;
  if (/\d/.test(s)) score += 15;
  if (/[^A-Za-z0-9]/.test(s)) score += 10;
  score = Math.max(0, Math.min(100, score));

  let label = 'Weak';
  if (score >= 80) label = 'Strong';
  else if (score >= 55) label = 'Good';
  else if (score >= 30) label = 'Fair';

  return { score, label };
}

function validateAuthForm() {
  const email = $('email').value;
  const pw = $('password').value;
  const name = $('fullName').value;

  let ok = true;
  setError('emailErr', '');
  setError('pwErr', '');
  setError('nameErr', '');

  if (!validateEmail(email)) {
    setError('emailErr', 'Enter a valid email address.');
    ok = false;
  }
  if (String(pw).length < 8) {
    setError('pwErr', 'Password must be at least 8 characters.');
    ok = false;
  }
  if (state.auth.mode === 'create') {
    if (!String(name).trim()) {
      setError('nameErr', 'Full Name is required.');
      ok = false;
    }
  }
  return ok;
}

/***********************
 * Heuristic Analyzer
 ***********************/
function normalizeText(s) {
  return String(s ?? '').toLowerCase();
}

function countHyphens(domainOrUrl) {
  return (String(domainOrUrl).match(/-/g) || []).length;
}

function looksLikeIpDomain(urlOrHost) {
  return /\b(\d{1,3}\.){3}\d{1,3}\b/.test(String(urlOrHost));
}

function urlHeuristics(inputUrl) {
  const raw = String(inputUrl || '').trim();
  const lower = normalizeText(raw);
  const reasons = [];

  let score = 0;

  if (lower.includes('https://')) {
    score -= 8;
    reasons.push({ kind: 'pos', text: 'Uses HTTPS scheme.' });
  } else {
    score += 18;
    reasons.push({ kind: 'neg', text: 'Missing HTTPS scheme.' });
  }

  const hyphens = countHyphens(raw);
  if (hyphens >= 3) {
    score += 10;
    reasons.push({ kind: 'neg', text: 'High hyphen count in domain/path (' + hyphens + ').' });
  } else if (hyphens === 0) {
    reasons.push({ kind: 'pos', text: 'No hyphen pattern detected in the URL.' });
    score -= 4;
  }

  const suspiciousKeywords = ['login', 'verify', 'secure', 'free', 'account', 'update'];
  const hits = suspiciousKeywords.filter((k) => lower.includes(k));
  if (hits.length) {
    score += 22;
    reasons.push({
      kind: 'neg',
      text:
        'Suspicious keyword(s) in URL: ' +
        hits.slice(0, 3).join(', ') +
        (hits.length > 3 ? '…' : '')
    });
  } else {
    reasons.push({ kind: 'pos', text: 'No common phishing keywords in the URL.' });
    score -= 8;
  }

  const riskyTlds = ['.xyz', '.top', '.club', '.loan', '.work', '.gq', '.tk', '.cf', '.ml', '.ru'];
  const risky = riskyTlds.filter((t) => lower.includes(t));
  if (risky.length) {
    score += 28;
    reasons.push({ kind: 'neg', text: 'Risky TLD detected: ' + risky[0] });
  } else {
    reasons.push({ kind: 'pos', text: 'TLD does not match common high-risk lists.' });
    score -= 6;
  }

  if (looksLikeIpDomain(raw)) {
    score += 25;
    reasons.push({ kind: 'neg', text: 'IP-address-like domain detected.' });
  } else {
    reasons.push({ kind: 'pos', text: 'Domain is not IP-address-like.' });
    score -= 4;
  }

  if (raw.length < 8) {
    score += 15;
    reasons.push({ kind: 'neg', text: 'URL is unusually short, may be obfuscated.' });
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  return { score, verdict: score >= 70 ? 'danger' : score >= 40 ? 'warning' : 'safe', reasons };
}

function textHeuristics(content) {
  const lower = normalizeText(content);
  const reasons = [];
  let score = 0;

  const urgency = ['urgent', 'immediately', 'act now', 'asap', 'within 24 hours', 'final notice'];
  const urgencyHits = urgency.filter((w) => lower.includes(w));
  if (urgencyHits.length) {
    score += 25;
    reasons.push({
      kind: 'neg',
      text: 'Urgency language detected: ' +
        urgencyHits.slice(0, 2).join(', ') +
        (urgencyHits.length > 2 ? '…' : '')
    });
  } else {
    reasons.push({ kind: 'pos', text: 'No strong urgency wording detected.' });
    score -= 7;
  }

  const sensitiveMentions = ['otp', 'one-time password', 'password', 'pin', 'verify your account', '2fa', 'mfa'];
  const sensHits = sensitiveMentions.filter((w) => lower.includes(w));
  if (sensHits.length) {
    score += 25;
    reasons.push({ kind: 'neg', text: 'Sensitive credential/verification indicators present.' });
  } else {
    reasons.push({ kind: 'pos', text: 'No obvious credential prompts detected.' });
    score -= 6;
  }

  const greetings = ['dear customer', 'valued customer', 'dear user', 'hello user', 'attention'];
  const gHits = greetings.filter((w) => lower.includes(w));
  if (gHits.length) {
    score += 10;
    reasons.push({ kind: 'neg', text: 'Generic greeting pattern detected.' });
  }

  const prize = ['prize', 'winner', 'lottery', 'free money', 'claim', 'congratulations', 'reward'];
  const pHits = prize.filter((w) => lower.includes(w));
  if (pHits.length) {
    score += 20;
    reasons.push({ kind: 'neg', text: 'Prize/lottery language detected.' });
  }

  const urlMatch = lower.match(/https?:\/\/[^\s"'<>]+/);
  if (urlMatch && urlMatch[0]) {
    const urlRes = urlHeuristics(urlMatch[0]);
    score += Math.round(urlRes.score * 0.35);
    reasons.push({
      kind: urlRes.score >= 70 ? 'neg' : urlRes.score >= 40 ? 'warn' : 'pos',
      text: 'Embedded link analysis influenced score.'
    });
  } else {
    reasons.push({ kind: 'pos', text: 'No embedded https:// link detected.' });
    score -= 3;
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  const verdict = score >= 70 ? 'danger' : score >= 40 ? 'warning' : 'safe';
  return { score, verdict, reasons };
}

function imageHeuristics() {
  const simulatedExtract =
    'Important: verify your account immediately. Login to confirm your security status. ' +
    'https://secure-free-login.xyz/verify?account=admin';

  const res = textHeuristics(simulatedExtract);
  res.reasons.unshift({ kind: 'warn', text: 'OCR simulation used (no real OCR in this build).' });
  return { ...res, extractedText: simulatedExtract };
}

function analyzeInput(type, content) {
  if (type === 'url') {
    const res = urlHeuristics(content);
    return { ...res, extractedText: null };
  }
  if (type === 'text') {
    const res = textHeuristics(content);
    return { ...res, extractedText: String(content || '').slice(0, 400) };
  }
  if (type === 'image') {
    const res = imageHeuristics(content);
    return { score: res.score, verdict: res.verdict, reasons: res.reasons, extractedText: res.extractedText };
  }
  return { score: 0, verdict: 'safe', reasons: [{ kind: 'pos', text: 'No analyzer available for this input.' }] };
}

/***********************
 * Render result
 ***********************/
function verdictMeta(verdict) {
  if (verdict === 'safe') return { label: 'Safe', icon: '✅', color: 'safe' };
  if (verdict === 'warning') return { label: 'Suspicious', icon: '⚠️', color: 'warning' };
  return { label: 'Phishing / Not Safe', icon: '❌', color: 'danger' };
}

function reasonIcon(kind) {
  if (kind === 'pos') return { glyph: '✔', cls: 'text-safe' };
  if (kind === 'neg') return { glyph: '✘', cls: 'text-danger' };
  if (kind === 'warn') return { glyph: '⚠', cls: 'text-warning' };
  return { glyph: '•', cls: 'text-text-dim' };
}

function escapeHtml(str) {
  return String(str)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '<')
    .replaceAll('>', '>')
    .replaceAll('"', '"')
    .replaceAll("'", '&#039;');
}





function renderResult(result) {
  state.analysis.lastResult = result;
  const score = result.riskScore ?? result.score ?? 0;
result.score = score;
  let verdict = result.verdict;

if (!verdict) {

    if (score >= 70) verdict = "danger";
    else if (score >= 40) verdict = "warning";
    else verdict = "safe";

}

const meta = verdictMeta(verdict);

  $('verdictLabel').textContent = meta.label;
  $('verdictSub').textContent = 'Heuristic scan complete — signals aggregated locally.';

  const iconBox = $('verdictIcon');
  iconBox.innerHTML = `<span class="text-2xl">${meta.icon}</span>`;
  iconBox.className = 'w-11 h-11 rounded-2xl flex items-center justify-center border text-' + meta.color;

 $('scorePct').textContent = score + '%';
  const bar = $('scoreBar');
 bar.style.width = score + '%';
  bar.className =
'h-full ' +
(verdict === 'safe' ? 'bg-safe' : verdict === 'warning' ? 'bg-warning' : 'bg-danger');

  const list = $('reasonsList');
  list.innerHTML = '';
  (result.reasons || []).slice(0, 8).forEach((r) => {
    const ic = reasonIcon(r.kind);
    const row = document.createElement('div');
    row.className = 'flex items-start gap-3 rounded-xl border border-border bg-bg/20 p-3';
    row.innerHTML = `
          <div class="font-mono text-sm ${ic.cls}">${ic.glyph}</div>
          <div>
            <div class="text-sm text-text">${escapeHtml(r.text)}</div>
          </div>
        `;
    list.appendChild(row);
  });

  const ocrBox = $('ocrBox');
  const ocrEmpty = $('ocrEmpty');
  const ocrTag = $('ocrTag');

  if (result.extractedText) {
    ocrEmpty.classList.add('hidden');
    ocrBox.classList.remove('hidden');
    ocrTag.textContent = 'FOUND';
    ocrBox.textContent = result.extractedText;
  } else {
    ocrBox.classList.add('hidden');
    ocrEmpty.classList.remove('hidden');
    ocrTag.textContent = '—';
  }
}

/***********************
 * Screen 2 chat + analyzer flow
 ***********************/
function setActiveMode(mode) {
  state.chat.activeMode = mode;
  document.querySelectorAll('.mode-tab').forEach((b) => {
    const active = b.dataset.mode === mode;
    b.setAttribute('aria-selected', active ? 'true' : 'false');
    b.className =
      'mode-tab px-4 py-2 rounded-xl border border-border bg-surface-2 ' +
      (active ? 'text-text' : 'text-text-dim') +
      ' hover:text-text focus:outline-none focus:ring-2 focus:ring-cyan-400';
  });

  $('modeUrl').classList.toggle('hidden', mode !== 'url');
  $('modeText').classList.toggle('hidden', mode !== 'text');
  $('modeImage').classList.toggle('hidden', mode !== 'image');
  updateAnalyzeEnabled();
}

function getActiveInput() {
  const mode = state.chat.activeMode;
  if (mode === 'url') return String($('urlInput').value || '').trim();
  if (mode === 'text') return String($('textInput').value || '').trim();
  if (mode === 'image') return state.chat.uploadedImage ? state.chat.uploadedImage : '';
  return '';
}

function updateAnalyzeEnabled() {
  const btn = $('analyzeBtn');
  const mode = state.chat.activeMode;
  if (mode === 'url') {
    const v = String($('urlInput').value || '').trim();
    btn.disabled = v.length < 6;
  } else if (mode === 'text') {
    const v = String($('textInput').value || '').trim();
    btn.disabled = v.length < 10;
  } else {
    btn.disabled = !state.chat.uploadedImage;
  }

  btn.className = btn.disabled
    ? 'flex-1 rounded-2xl bg-accent/20 text-accent font-semibold px-4 py-3 border border-accent/30 disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-cyan-400'
    : 'flex-1 rounded-2xl bg-accent text-bg font-semibold px-4 py-3 border border-transparent hover:opacity-95 focus:outline-none focus:ring-2 focus:ring-cyan-400';
}

function appendChatBubble(userText) {
  const log = $('chatLog');
  const wrapper = document.createElement('div');
  wrapper.className = 'flex justify-end';
  wrapper.innerHTML = `
        <div class="max-w-xl">
          <div class="rounded-2xl border border-accent/30 bg-accent/10 px-4 py-2 text-sm">
            <div class="text-text">${escapeHtml(userText)}</div>
          </div>
        </div>
      `;
  log.appendChild(wrapper);
  log.scrollTop = log.scrollHeight;
}

function appendAssistantTyping() {
  const log = $('chatLog');
  const wrapper = document.createElement('div');
  wrapper.className = 'flex';
  wrapper.id = 'typingRow';
  wrapper.innerHTML = `
        <div class="max-w-xl">
          <div class="inline-flex items-center rounded-2xl border border-border bg-surface-2 px-4 py-2 text-sm text-text-dim">
            <span class="mr-2">ShieldAI</span>
            <span class="font-mono">processing</span>
            <span class="ml-3 flex gap-1">
              <span class="w-1.5 h-1.5 rounded-full bg-accent animate-[bounce_0.8s_infinite_0ms]"></span>
              <span class="w-1.5 h-1.5 rounded-full bg-accent animate-[bounce_0.8s_infinite_150ms]"></span>
              <span class="w-1.5 h-1.5 rounded-full bg-accent animate-[bounce_0.8s_infinite_300ms]"></span>
            </span>
          </div>
        </div>
      `;

  const style = document.createElement('style');
  style.textContent = `@keyframes bounce {0%,100%{transform:translateY(0)}50%{transform:translateY(-4px)}}`;
  document.head.appendChild(style);

  log.appendChild(wrapper);
}

function removeTyping() {
  const row = $('typingRow');
  if (row) row.remove();
}

/***********************
 * Wire up UI events
 ***********************/
// =====================================
// Authentication API Functions
// =====================================

// Signup API
async function signupUser(name, email, password) {

    try {

        const response = await fetch(`${API_BASE}/signup`, {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                name,
                email,
                password
            })

        });

        const data = await response.json();

        return data;

    } catch (error) {

        console.error("Signup Error:", error);

        return {
            success: false,
            message: "Unable to connect to server."
        };

    }

}


// Login API
async function loginUser(email, password) {

    try {

        const response = await fetch(`${API_BASE}/login`, {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                email,
                password
            })

        });

        const data = await response.json();

        return data;

    } catch (error) {

        console.error("Login Error:", error);

        return {
            success: false,
            message: "Unable to connect to server."
        };

    }

}
async function getProfile() {

    const token = localStorage.getItem("token");

    const response = await fetch(`${API_BASE}/profile`, {

        method: "GET",

        headers: {
            Authorization: `Bearer ${token}`
        }

    });

    return await response.json();

}
function wireAuth() {
  $('tabSignIn').addEventListener('click', () => setAuthTab('signin'));
  $('tabCreate').addEventListener('click', () => setAuthTab('create'));
  setAuthTab('create');

  $('togglePw').addEventListener('click', () => {
    const pw = $('password');
    const iconEye = $('iconEye');
    const iconEyeSlash = $('iconEyeSlash');

    if (!pw) return;
    const isHidden = pw.type === 'password';
    pw.type = isHidden ? 'text' : 'password';

    // Swap icons to match the current state.
    if (iconEye && iconEyeSlash) {
      iconEye.classList.toggle('hidden', !isHidden);
      iconEyeSlash.classList.toggle('hidden', isHidden);
    }
  });


  $('password').addEventListener('input', () => {
    const pw = $('password').value;
    if (state.auth.mode !== 'create') return;
    const { score, label } = passwordStrength(pw);
    $('pwStrengthLabel').textContent = label;
    const bar = $('pwStrengthBar');
    bar.style.width = score + '%';
    bar.className = 'h-full transition-all ' + (score >= 80 ? 'bg-safe' : score >= 55 ? 'bg-warning' : 'bg-danger');
  });

  $('remember').addEventListener('change', (e) => {
    state.auth.remembered = !!e.target.checked;
  });

  $('forgot').addEventListener('click', (e) => {
    e.preventDefault();
    showToast('Password reset is unavailable in this demo UI.');
  });


    $('authForm').addEventListener('submit', async (e) => {

    e.preventDefault();

    const ok = validateAuthForm();

    if (!ok) {
        showToast("Fix the highlighted fields to continue.");
        return;
    }

    $('authSubmit').disabled = true;
    $('authLoading').classList.remove('hidden');

    const email = $('email').value.trim();
    const password = $('password').value.trim();

    let response;

    if (state.auth.mode === "create") {

        const name = $('fullName').value.trim();

        response = await signupUser(name, email, password);

    } else {

        response = await loginUser(email, password);

    }

    $('authSubmit').disabled = false;
    $('authLoading').classList.add('hidden');

    if (!response.success) {

        showToast(response.message || "Something went wrong.");
        return;

    }

    localStorage.setItem("token", response.token);

    state.auth.user = {
        email,
        name: state.auth.mode === "create"
            ? $('fullName').value.trim()
            : response.user?.name || ""
    };

    showScreen('screen2');

    state.chat.uploadedImage = null;
    state.chat.uploadedImagePreviewUrl = null;

    $('imagePreviewWrap').classList.add('hidden');

    const smartInput = $('smartInput');

    if (smartInput) smartInput.value = '';

    $('fileInput').value = '';

    $('chatLog').innerHTML = `
        <div class="flex">
            <div class="max-w-xl">
                <div class="inline-flex items-center rounded-2xl border border-border bg-surface-2 px-4 py-2 text-sm">
                    <span class="text-text-dim">&nbsp;</span>
                    <span class="text-sm text-text">
                        Paste content and press
                        <span class="text-accent font-semibold">Analyze</span>.
                        I'll return a risk verdict.
                    </span>
                </div>
            </div>
        </div>
    `;

});
}
/**
 * Clean OCR text by normalizing whitespace and punctuation
 * while preserving URLs, email addresses, and numbers.
 */
function cleanOCRText(text) {

    if (!text || typeof text !== "string") return "";

    const preserved = [];
    const PLACEHOLDER_PREFIX = "___OCR_PRESERVE_";

    // Preserve URLs
    let cleaned = text.replace(
        /(https?:\/\/[^\s"'<>{}|\\^`[\]]+)/gi,
        (match) => {
            const idx = preserved.length;
            preserved.push(match);
            return `${PLACEHOLDER_PREFIX}${idx}___`;
        }
    );

    // Preserve emails
    cleaned = cleaned.replace(
        /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/gi,
        (match) => {
            const idx = preserved.length;
            preserved.push(match);
            return `${PLACEHOLDER_PREFIX}${idx}___`;
        }
    );

    // Preserve numbers
    cleaned = cleaned.replace(
        /\b\d+[\.,]?\d*%?\b/g,
        (match) => {
            const idx = preserved.length;
            preserved.push(match);
            return `${PLACEHOLDER_PREFIX}${idx}___`;
        }
    );

    // Normalize spaces
    cleaned = cleaned.replace(/[ \t]+/g, " ");

    // Normalize newlines
    cleaned = cleaned.replace(/\r\n/g, "\n");
    cleaned = cleaned.replace(/\r/g, "\n");
    cleaned = cleaned.replace(/\n{3,}/g, "\n\n");

    // Remove repeated punctuation
    cleaned = cleaned.replace(/([!?]){2,}/g, "$1");
    cleaned = cleaned.replace(/([.,;:]){2,}/g, "$1");
    cleaned = cleaned.replace(/(?<!\w)([-_]){2,}(?!\w)/g, "$1");

    // Ensure space after period
    cleaned = cleaned.replace(/\.([A-Z])/g, ". $1");

    // Restore preserved tokens
    cleaned = cleaned.replace(
        /___OCR_PRESERVE_(\d+)___/g,
        (_, num) => preserved[parseInt(num, 10)] || ""
    );

    return cleaned.trim();
}

/**
 * Extract text from image using Tesseract OCR
 */
async function extractTextFromImage(file) {

    try {

        showToast("Running OCR...");

        const {
            data
        } = await Tesseract.recognize(
            file,
            "eng",
            {
                logger: (m) => {

                    if (m.status === "recognizing text") {

                        const progress = Math.round((m.progress || 0) * 100);

                        console.log("OCR Progress:", progress + "%");

                    }

                }
            }
        );

        const confidence = Math.round(data.confidence || 0);

        console.log("OCR Confidence:", confidence + "%");

        state.analysis.ocrConfidence = confidence;

        const cleanedText = cleanOCRText(data.text || "");

        console.log("OCR Text:", cleanedText);

        return cleanedText;

    } catch (err) {

        console.error("OCR Error:", err);

        showToast("OCR failed.");

        return "";

    }

}

function wireScanConsole() {
  const smartInput = $('smartInput');
  const smartUploadBox = $('smartUploadBox');
  const fileInput = $('fileInput');
  const browseBtn = $('browseBtn');
  const preview = $('imagePreview');
  const previewWrap = $('imagePreviewWrap');
  const clearImage = $('clearImage');
  const analyzeBtn = $('analyzeBtn');
  const analysisOverlay = $('analysisOverlay');
  const analysisProgressBar = $('analysisProgressBar');

  if (!smartInput || !smartUploadBox || !fileInput || !preview || !previewWrap || !analyzeBtn) {
    // If the DOM is out of sync, fail softly instead of throwing.
    console.warn('ShieldAI UI wiring incomplete: required elements not found.');
    return;
  }

  function setOverlayActive(active) {
    if (!analysisOverlay) return;
    if (active) {
      analysisOverlay.classList.remove('hidden');
      analysisOverlay.classList.add('active');
      if (analysisProgressBar) {
        analysisProgressBar.style.width = '15%';
      }
    } else {
      analysisOverlay.classList.add('hidden');
      analysisOverlay.classList.remove('active');
      if (analysisProgressBar) analysisProgressBar.style.width = '0%';
    }
  }

  function getTextContent() {
    return String(smartInput.value || '').trim();
  }

  function updateAnalyzeEnabledLocal() {
    const text = getTextContent();
    const hasImage = !!state.chat.uploadedImage;
    const hasTextEnough = text.length >= 6;
    analyzeBtn.disabled = !(hasImage || hasTextEnough);
    analyzeBtn.className = analyzeBtn.disabled
      ? 'flex-1 rounded-2xl bg-accent/20 text-accent font-semibold px-4 py-3 border border-accent/30 disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-cyan-400'
      : 'flex-1 rounded-2xl bg-accent text-bg font-semibold px-4 py-3 border border-transparent hover:opacity-95 focus:outline-none focus:ring-2 focus:ring-cyan-400';
  }

  smartInput.addEventListener('input', updateAnalyzeEnabledLocal);

  if (browseBtn) {
    browseBtn.addEventListener('click', () => fileInput.click());
  }

  // Drag & drop for screenshot uploads
  // Note: file picker is intentionally opened only via the Browse button.
  // Drag & drop is still supported.

  // (No click handler on smartUploadBox.)


  smartUploadBox.addEventListener('dragover', (e) => {
    e.preventDefault();
    smartUploadBox.classList.add('border-accent/60');
  });
  smartUploadBox.addEventListener('dragleave', () => smartUploadBox.classList.remove('border-accent/60'));
  smartUploadBox.addEventListener('drop', (e) => {
    e.preventDefault();
    smartUploadBox.classList.remove('border-accent/60');
    const file = e.dataTransfer?.files?.[0];
    if (file) handleImageFile(file);
  });

  fileInput.addEventListener('change', (e) => {
    const file = e.target.files?.[0];
    if (file) handleImageFile(file);
  });

  function handleImageFile(file) {
    state.chat.uploadedImage = file;
    if (state.chat.uploadedImagePreviewUrl) URL.revokeObjectURL(state.chat.uploadedImagePreviewUrl);
    state.chat.uploadedImagePreviewUrl = URL.createObjectURL(file);

    preview.src = state.chat.uploadedImagePreviewUrl;
    previewWrap.classList.remove('hidden');
    updateAnalyzeEnabledLocal();
  }

  if (clearImage) {
    clearImage.addEventListener('click', () => {
      if (state.chat.uploadedImagePreviewUrl) URL.revokeObjectURL(state.chat.uploadedImagePreviewUrl);
      state.chat.uploadedImage = null;
      state.chat.uploadedImagePreviewUrl = null;
      fileInput.value = '';
      previewWrap.classList.add('hidden');
      preview.src = '';
      updateAnalyzeEnabledLocal();
    });
  }

  function detectTypeForText(text) {
    const lower = String(text || '').toLowerCase();
    const looksUrl = lower.startsWith('http://') || lower.startsWith('https://') || /\./.test(lower);
    return looksUrl ? 'url' : 'text';
  }

  analyzeBtn.addEventListener('click', async () => {
    const text = getTextContent();
    const hasImage = !!state.chat.uploadedImage;

    if (!hasImage && text.length < 6) return;

    let mode;
    let content;
    if (hasImage) {

    mode = "image";

    appendChatBubble(
        "Screenshot uploaded (" +
        state.chat.uploadedImage.name +
        ")"
    );

    const extractedText =
        await extractTextFromImage(state.chat.uploadedImage);

    if (!extractedText) {

        showToast("No text detected in image.");

        removeTyping();
        analyzeBtn.disabled = false;
        setOverlayActive(false);

        return;

    }

    content = extractedText;

} else {
      mode = detectTypeForText(text);
      content = text;
      appendChatBubble(text.slice(0, 220) + (text.length > 220 ? '…' : ''));
    }

    appendAssistantTyping();
    analyzeBtn.disabled = true;
    setOverlayActive(true);

    const payload = { type: mode, content };
    state.analysis.lastInput = payload;

    (async () => {

    try {

       const token = localStorage.getItem("token");

const headers = {
    "Content-Type": "application/json"
};

if (token) {
    headers.Authorization = `Bearer ${token}`;
}

const response = await fetch(
    "https://cybershield-production-64c0.up.railway.app/api/scan/analyze",
    {
        method: "POST",
        headers,
        body: JSON.stringify({
            input: content,
            inputType: mode
        })
    }
);

      
       const responseData = await response.json();

console.log("========== FULL API RESPONSE ==========");
console.log(JSON.stringify(responseData, null, 2));
console.log("=======================================");
if (!response.ok || !responseData.success) {

    removeTyping();
    analyzeBtn.disabled = false;
    setOverlayActive(false);

    showToast(responseData.message || "Analysis failed.");

    return;

}
if (mode === "image") {

    responseData.result.extractedText = content;

    responseData.result.ocrStatus = "SUCCESS";

}

removeTyping();
analyzeBtn.disabled = false;
setOverlayActive(false);

renderResult(responseData.result);

showScreen("screen3");

    } catch (err) {

        removeTyping();
        analyzeBtn.disabled = false;
        setOverlayActive(false);

        showToast("Unable to connect to Scan API");

        console.error(err);

    }

})();
  });

  updateAnalyzeEnabledLocal();
}


function wireResultScreen() {
  $('scanAnother').addEventListener('click', () => {
    const resultToast = $('resultToast');
    if (resultToast) resultToast.classList.add('hidden');
    state.analysis.lastResult = null;
    state.analysis.lastInput = null;

    const smartInput = $('smartInput');
    if (smartInput) smartInput.value = '';

    if (state.chat.uploadedImagePreviewUrl) URL.revokeObjectURL(state.chat.uploadedImagePreviewUrl);
    state.chat.uploadedImage = null;
    state.chat.uploadedImagePreviewUrl = null;

    const fileInput = $('fileInput');
    if (fileInput) fileInput.value = '';

    const imagePreviewWrap = $('imagePreviewWrap');
    if (imagePreviewWrap) imagePreviewWrap.classList.add('hidden');

    const imagePreview = $('imagePreview');
    if (imagePreview) imagePreview.src = '';

    $('chatLog').innerHTML = `
          <div class="flex">
            <div class="max-w-xl">
              <div class="inline-flex items-center rounded-2xl border border-border bg-surface-2 px-4 py-2 text-sm">
                <span class="text-text-dim">&nbsp;</span>
                <span class="text-sm text-text">Paste content and press <span class="text-accent font-semibold">Analyze</span>. I&apos;ll return a risk verdict.</span>
              </div>
            </div>
          </div>
        `;

    // Re-enable analyze button based on current state.
    const analyzeBtn = $('analyzeBtn');
    if (analyzeBtn) {
      analyzeBtn.disabled = !(smartInput && smartInput.value.trim().length >= 6) && !(state.chat.uploadedImage);
    }

    showScreen('screen2');
  });

 $('downloadReport').addEventListener('click', () => {

    const result = state.analysis.lastResult;

    if (!result) {
        showToast("No report available.");
        return;
    }

    populateReport(result);

    showScreen('screen4');

});
$('scanAgainFromReport').addEventListener('click', () => {

    state.analysis.lastResult = null;
    state.analysis.lastInput = null;

    // Clear input
    if ($('smartInput')) $('smartInput').value = '';

    // Clear uploaded image
    state.chat.uploadedImage = null;

    if (state.chat.uploadedImagePreviewUrl) {
        URL.revokeObjectURL(state.chat.uploadedImagePreviewUrl);
        state.chat.uploadedImagePreviewUrl = null;
    }

    if ($('imagePreview')) $('imagePreview').src = "";

    if ($('imagePreviewWrap'))
        $('imagePreviewWrap').classList.add("hidden");

    if ($('fileInput'))
        $('fileInput').value = "";

    showScreen('screen2');

});
$('backToResult').addEventListener('click', () => {

    showScreen('screen3');

});
}

/***********************
 * InitS
 ***********************/
function populateReport(result) {

    const score = Number(result.riskScore || result.score || 0);

    // baaki sara code yahi se start hoga   

    // --------------------------
    // Basic Info
    // --------------------------

    document.getElementById("reportInput").textContent =
        result.input || "-";

    document.getElementById("reportTime").textContent =
        new Date().toLocaleString();

    document.getElementById("reportId").textContent =
        "CS-" + Date.now();

    // --------------------------
    // Verdict
    // --------------------------

    let verdict;
let badge;
let threat;

const priorityBadge = document.getElementById("actionPriorityBadge");
const immediateCard = document.getElementById("immediateActionCard");
const avoidCard = document.getElementById("avoidActionsCard");

if (score < 30) {

    verdict = "Safe";
    badge = "LOW";
    threat = "Website appears safe.";

    if (priorityBadge) priorityBadge.style.display = "none";
    if (immediateCard) immediateCard.style.display = "none";
    if (avoidCard) avoidCard.style.display = "none";

}
if (score < 30) {

    if (priorityBadge) priorityBadge.style.display = "none";
    if (immediateCard) immediateCard.style.display = "none";
    if (avoidCard) avoidCard.style.display = "none";

}
else if (score < 70) {

    verdict = "Suspicious";
    badge = "MEDIUM";
    threat = "Proceed with caution. Verify before continuing.";

    if (priorityBadge) priorityBadge.style.display = "none";
    if (immediateCard) immediateCard.style.display = "";
    if (avoidCard) avoidCard.style.display = "none";

}
else {

    verdict = "Phishing / Not Safe";
    badge = "HIGH";
    threat = "This website is likely phishing.";

    if (priorityBadge) priorityBadge.style.display = "";
    if (immediateCard) immediateCard.style.display = "";
    if (avoidCard) avoidCard.style.display = "";

}

    

    document.getElementById("reportRiskScore").textContent = score + "%";
    document.getElementById("reportVerdict").textContent = verdict;
    document.getElementById("reportThreatBadge").textContent = badge;
    const threatBadge = document.getElementById("reportThreatBadge");

threatBadge.classList.remove(
    "bg-green-500",
    "bg-yellow-500",
    "bg-red-500"
);

if (score < 30) {
    threatBadge.classList.add("bg-green-500");
}
else if (score < 70) {
    threatBadge.classList.add("bg-yellow-500");
}
else {
    threatBadge.classList.add("bg-red-500");
}
    document.getElementById("reportVerdictBadge").textContent = badge;
   const verdictBadge = document.getElementById("reportVerdictBadge");

verdictBadge.classList.remove(
    "bg-green-500",
    "bg-yellow-500",
    "bg-red-500"
);

if (score < 30) {
    verdictBadge.classList.add("bg-green-500");
}
else if (score < 70) {
    verdictBadge.classList.add("bg-yellow-500");
}
else {
    verdictBadge.classList.add("bg-red-500");
}
const levelBadge = document.getElementById("reportThreatLevelBadge");
console.log("levelBadge =", levelBadge);
console.log("score =", score);

levelBadge.classList.remove(
    "bg-danger/20",
    "text-danger",
    "bg-warning/20",
    "text-warning",
    "bg-safe/20",
    "text-safe"
);

if (score < 30) {
  console.log("LOW BLOCK");

    levelBadge.textContent = "LOW";
    levelBadge.classList.add("bg-safe/20", "text-safe");

}
else if (score < 70) {

    levelBadge.textContent = "MEDIUM";
    levelBadge.classList.add("bg-warning/20", "text-warning");

}
else {

    levelBadge.textContent = "HIGH";
    levelBadge.classList.add("bg-danger/20", "text-danger");

}

    document.getElementById("reportThreatMessage").textContent = threat;

    // --------------------------
    // AI
    // --------------------------

    document.getElementById("reportAIReason").textContent =
        result.aiAnalysis?.reason ||
        "No AI analysis available.";

    document.getElementById("reportAIVerdict").textContent =
    result.aiAnalysis?.risk || verdict;

   const aiConfidence =
    result.aiAnalysis?.confidence ?? 95;

document.getElementById("reportAIConfidence").textContent =
    aiConfidence + "%";

    // --------------------------
    // VirusTotal
    // --------------------------

    const vt = result.virusTotal || {};

    document.getElementById("reportVTMalicious").textContent =
        vt.malicious ?? 0;

    document.getElementById("reportVTSuspicious").textContent =
        vt.suspicious ?? 0;

    document.getElementById("reportVTHarmless").textContent =
        vt.harmless ?? 0;

    document.getElementById("reportVTUndetected").textContent =
        vt.undetected ?? 0;

    // --------------------------
    // SSL
    // --------------------------

    const ssl = result.ssl || {};

   document.getElementById("reportSSLStatus").textContent =
    ssl.valid ? "Valid" : "Invalid";

document.getElementById("reportSSLBadge").textContent =
    ssl.valid ? "VALID" : "INVALID";

document.getElementById("reportSSLIssuer").textContent =
    ssl.issuer || "Unknown";

document.getElementById("reportSSLExpiry").textContent =
    ssl.validTo || "Unknown";
    // --------------------------
    // WHOIS
    // --------------------------

    const whois = result.whois || {};

document.getElementById("reportRegistrar").textContent =
    whois.registrar || "Unknown";

document.getElementById("reportCountry").textContent =
    whois.country || "Unknown";

document.getElementById("reportOrganization").textContent =
    whois.organization || "Unknown";

document.getElementById("reportCreatedDate").textContent =
    whois.creationDate || "Unknown";
    // --------------------------
    // Domain
    // --------------------------

   document.getElementById("reportDomainAge").textContent =
    result.domainAge?.ageInYears || "Unknown";

    document.getElementById("reportDomainRisk").textContent =
        score >= 70 ? "High" :
        score >= 40 ? "Medium" : "Low";

    // --------------------------
    // Risk Factors
    // --------------------------

    const box = document.getElementById("reportRiskFactors");

    box.innerHTML = "";

    const factors =
        result.reasons ||
        result.riskFactors ||
        [];

    if (!factors.length) {

        box.innerHTML =
            `<div class="rounded-xl bg-bg/30 border border-border p-4">
                • No risk factors available.
            </div>`;

    } else {

        factors.forEach(item => {

            const div = document.createElement("div");

            div.className =
                "rounded-xl bg-bg/30 border border-border p-4";

           div.textContent =
    "• " + (item.text || item);
            box.appendChild(div);

        });

    }
  }

(function init() {
  wireAuth();
  wireScanConsole();
  wireResultScreen();
})();

