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

const $ = (id) => document.getElementById(id);

function showToast(message) {
  const t = $('globalToast');
  t.textContent = message;
  t.classList.remove('hidden');
  clearTimeout(showToast._timer);
  showToast._timer = setTimeout(() => t.classList.add('hidden'), 2200);
}

function showScreen(id) {
  ['screen1', 'screen2', 'screen3'].forEach((s) => $(s).classList.add('hidden'));
  $(id).classList.remove('hidden');
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
  const meta = verdictMeta(result.verdict);

  $('verdictLabel').textContent = meta.label;
  $('verdictSub').textContent = 'Heuristic scan complete — signals aggregated locally.';

  const iconBox = $('verdictIcon');
  iconBox.innerHTML = `<span class="text-2xl">${meta.icon}</span>`;
  iconBox.className = 'w-11 h-11 rounded-2xl flex items-center justify-center border text-' + meta.color;

  $('scorePct').textContent = result.score + '%';
  const bar = $('scoreBar');
  bar.style.width = result.score + '%';
  bar.className = 'h-full ' + (result.verdict === 'safe' ? 'bg-safe' : result.verdict === 'warning' ? 'bg-warning' : 'bg-danger');

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
function wireAuth() {
  $('tabSignIn').addEventListener('click', () => setAuthTab('signin'));
  $('tabCreate').addEventListener('click', () => setAuthTab('create'));
  setAuthTab('create');

  $('togglePw').addEventListener('click', () => {
    const pw = $('password');
    const isHidden = pw.type === 'password';
    pw.type = isHidden ? 'text' : 'password';
    $('togglePw').textContent = isHidden ? 'Hide' : 'Show';
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

  $('authForm').addEventListener('submit', (e) => {
    e.preventDefault();

    const ok = validateAuthForm();
    if (!ok) {
      showToast('Fix the highlighted fields to continue.');
      return;
    }

    $('authSubmit').disabled = true;
    $('authLoading').classList.remove('hidden');

    setTimeout(() => {
      $('authSubmit').disabled = false;
      $('authLoading').classList.add('hidden');

      state.auth.user = {
        email: $('email').value.trim(),
        name: state.auth.mode === 'create' ? $('fullName').value.trim() : null
      };

      showScreen('screen2');

      state.chat.uploadedImage = null;
      state.chat.uploadedImagePreviewUrl = null;
      $('imagePreviewWrap').classList.add('hidden');
      $('urlInput').value = '';
      $('textInput').value = '';
      $('fileInput').value = '';

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

      setActiveMode('url');
    }, 650);
  });
}

function wireScanConsole() {
  document.querySelectorAll('.mode-tab').forEach((btn) => {
    btn.addEventListener('click', () => setActiveMode(btn.dataset.mode));
  });

  $('urlInput').addEventListener('input', updateAnalyzeEnabled);
  $('textInput').addEventListener('input', updateAnalyzeEnabled);

  const dropZone = $('dropZone');
  const fileInput = $('fileInput');
  const preview = $('imagePreview');
  const previewWrap = $('imagePreviewWrap');
  const clearImage = $('clearImage');

  dropZone.addEventListener('click', () => fileInput.click());
  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('border-accent/60');
  });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('border-accent/60'));
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('border-accent/60');
    const file = e.dataTransfer.files?.[0];
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
    updateAnalyzeEnabled();
  }

  clearImage.addEventListener('click', () => {
    if (state.chat.uploadedImagePreviewUrl) URL.revokeObjectURL(state.chat.uploadedImagePreviewUrl);
    state.chat.uploadedImage = null;
    state.chat.uploadedImagePreviewUrl = null;
    fileInput.value = '';
    previewWrap.classList.add('hidden');
    preview.src = '';
    updateAnalyzeEnabled();
  });

  $('analyzeBtn').addEventListener('click', () => {
    const mode = state.chat.activeMode;
    const input = getActiveInput();

    if (mode === 'url' && String(input).length < 6) return;
    if (mode === 'text' && String(input).length < 10) return;
    if (mode === 'image' && !state.chat.uploadedImage) return;

    if (mode === 'image') {
      appendChatBubble('Screenshot uploaded (' + state.chat.uploadedImage.name + ')');
    } else {
      appendChatBubble(String(input).slice(0, 220) + (String(input).length > 220 ? '…' : ''));
    }

    appendAssistantTyping();
    $('analyzingIndicator').classList.remove('hidden');
    $('analyzeBtn').disabled = true;

    const payload = {
      type: mode,
      content: mode === 'image' ? state.chat.uploadedImage : input
    };
    state.analysis.lastInput = payload;

    setTimeout(() => {
      const result = analyzeInput(mode, payload.content);

      removeTyping();
      $('analyzingIndicator').classList.add('hidden');
      $('analyzeBtn').disabled = false;

      renderResult(result);
      showScreen('screen3');
    }, 1300);
  });
}

function wireResultScreen() {
  $('scanAnother').addEventListener('click', () => {
    $('resultToast').classList.add('hidden');
    state.analysis.lastResult = null;
    state.analysis.lastInput = null;

    $('urlInput').value = '';
    $('textInput').value = '';

    if (state.chat.uploadedImagePreviewUrl) URL.revokeObjectURL(state.chat.uploadedImagePreviewUrl);
    state.chat.uploadedImage = null;
    state.chat.uploadedImagePreviewUrl = null;
    $('fileInput').value = '';

    $('imagePreviewWrap').classList.add('hidden');
    $('imagePreview').src = '';

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

    setActiveMode('url');
    showScreen('screen2');
  });

  $('downloadReport').addEventListener('click', () => {
    const t = $('resultToast');
    t.classList.remove('hidden');
    t.textContent = 'Report download is a placeholder in this demo (no PDF generation).';
    setTimeout(() => t.classList.add('hidden'), 2600);
    showToast('Report download is a demo placeholder.');
  });
}

/***********************
 * Init
 ***********************/
(function init() {
  wireAuth();
  wireScanConsole();
  wireResultScreen();
})();

