/**
 * Cloudflare Clean IP Scanner - Frontend Client Logic
 * Handles SSE streams, real-time latency sorting, clipboard actions, and bilingual localization.
 */

// State
const state = {
  lang: 'fa', // 'fa' or 'en'
  currentAsn: '13335',
  totalPrefixes: 0,
  isRunning: false,
  isPaused: false,
  workingResults: [], // Array of working ScanResult objects sorted by google_latency_ms
  testedCount: 0,
  totalCount: 0,
  speed: 0,
  bestPing: Infinity,
  searchFilter: '',
  eventSource: null,
};

// Bilingual dictionary
const i18n = {
  fa: {
    appTitle: 'اسکنر آی‌پی تمیز کلادفلر',
    appSubtitle: 'Cloudflare Clean IP Scanner (HE BGP Super-LG API)',
    asnTitle: 'شماره خودگردان (ASN):',
    fetchBgp: 'بروزرسانی رنج‌ها',
    prefixesLoaded: (n) => `${n.toLocaleString('fa-IR')} پیشوند لود شد`,
    configInputTitle: 'کانفیگ پروکسی / دامنه',
    configPlaceholder: 'کانفیگ خود را اینجا پیست کنید (vless://, vmess://, trojan://, ss:// یا دامنه/ورکر)\nمثال:\nvless://uuid@myworker.example.workers.dev:443?type=ws&security=tls&path=%2F%3Fed%3D2560&host=myworker.example.workers.dev&sni=myworker.example.workers.dev#MyWorker',
    sniLabel: 'SNI / دامنه:',
    portLabel: 'پورت:',
    transportLabel: 'انتقال:',
    pathLabel: 'مسیر:',
    scanParamsTitle: 'تنظیمات اسکن و تست',
    sampleModeLabel: 'استراتژی نمونه‌برداری از ساب‌نت‌ها:',
    optRandom: '🎲 نمونه تصادفی در هر پیشوند (پیشنهادی)',
    optGateway: '🎯 آی‌پی‌های لبه (.1, .10, .50, .100, .200)',
    optStep: '⚡ گام‌های متوالی در ساب‌نت (Step Stride)',
    optCustom: '📋 لیست دستی آی‌پی‌ها',
    targetUrlLabel: 'مقصد تست سلامت و Latency:',
    ipsPerPrefixLabel: 'تعداد آی‌پی از هر پیشوند:',
    maxIpsLabel: 'حداکثر کل آی‌پی‌ها:',
    concurrencyLabel: 'تعداد تردهای همزمان (Concurrency):',
    timeoutLabel: 'مهلت پاسخ (Timeout):',
    seconds: 'ثانیه',
    customIpsLabel: 'لیست آی‌پی‌ها یا ساب‌نت‌های دلخواه (هر خط یک مورد):',
    startScan: 'شروع اسکن آی‌پی‌ها',
    realdelayBtn: 'تست تاخیر واقعی (RealDelay)',
    realdelayTesting: 'در حال تست تاخیر واقعی (RealDelay)...',
    realdelayDone: 'تست تاخیر واقعی به پایان رسید!',
    thRealDelay: 'تاخیر واقعی (RealDelay)',
    pauseScan: 'توقف موقت',
    resumeScan: 'ادامه اسکن',
    stopScan: 'لغو اسکن',
    clearTable: 'پاکسازی',
    testedLabel: 'تست شده / کل',
    workingLabel: 'آی‌پی سالم پیدا شده',
    speedLabel: 'سرعت اسکن',
    bestPingLabel: 'بهترین پینگ گوگل',
    resultsTableTitle: 'آی‌پی‌های سالم و مرتب‌شده بر اساس پینگ گوگل (204)',
    resultsCount: (n) => `${n.toLocaleString('fa-IR')} مورد`,
    searchPlaceholder: 'فیلتر آی‌پی یا ساب‌نت...',
    copyAll: 'کپی آی‌پی‌ها',
    export: 'خروجی',
    exportIps: '📄 لیست آی‌پی‌ها (TXT)',
    exportConfigs: '🔗 لینک‌های آماده کانفیگ (TXT)',
    exportCsv: '📊 جدول اکسل (CSV)',
    exportJson: '💾 ساختار کامل (JSON)',
    thRank: '#',
    thIp: 'آدرس آی‌پی',
    thPrefix: 'پیشوند / CIDR',
    thGoogle: 'پینگ گوگل (204) ↓',
    thTcp: 'TCP Latency',
    thTls: 'TLS Handshake',
    thStatus: 'وضعیت تست',
    thActions: 'عملیات',
    noResultsTitle: 'هنوز اسکن شروع نشده است',
    noResultsDesc: 'کانفیگ خود را وارد کرده و دکمه «شروع اسکن آی‌پی‌ها» را بزنید.',
    readyText: 'آماده شروع اسکن',
    scanningText: 'در حال اسکن...',
    pausedText: 'اسکن متوقف شد',
    finishedText: 'اسکن پایان یافت',
    copiedIp: 'آی‌پی کپی شد!',
    copiedConfig: 'کانفیگ با آی‌پی جدید کپی شد!',
    copiedAllIps: (n) => `${n} آی‌پی سالم به کلیپ‌بورد کپی شد!`,
    retesting: 'در حال تست مجدد...',
  },
  en: {
    appTitle: 'Cloudflare Clean IP Scanner',
    appSubtitle: 'Hurricane Electric BGP Super-LG API & Google 204 Connectivity Check',
    asnTitle: 'Autonomous System (ASN):',
    fetchBgp: 'Refresh Prefixes',
    prefixesLoaded: (n) => `${n.toLocaleString()} prefixes loaded`,
    configInputTitle: 'Proxy Configuration / Domain',
    configPlaceholder: 'Paste your proxy link here (vless://, vmess://, trojan://, ss:// or domain)\nExample:\nvless://uuid@myworker.example.workers.dev:443?type=ws&security=tls&path=%2F%3Fed%3D2560&host=myworker.example.workers.dev&sni=myworker.example.workers.dev#MyWorker',
    sniLabel: 'SNI / Domain:',
    portLabel: 'Port:',
    transportLabel: 'Transport:',
    pathLabel: 'Path:',
    scanParamsTitle: 'Scan & Latency Settings',
    sampleModeLabel: 'Subnet Sampling Strategy:',
    optRandom: '🎲 Random IPs per Prefix (Recommended)',
    optGateway: '🎯 Edge Gateway IPs (.1, .10, .50, .100, .200)',
    optStep: '⚡ Equal Step Stride per Subnet',
    optCustom: '📋 Custom Manual IP List',
    targetUrlLabel: 'Latency & Health Check Target:',
    ipsPerPrefixLabel: 'IPs per Prefix:',
    maxIpsLabel: 'Max Total Candidate IPs:',
    concurrencyLabel: 'Concurrent Worker Threads:',
    timeoutLabel: 'Response Timeout:',
    seconds: 'sec',
    customIpsLabel: 'Custom IPs or Subnets (one per line):',
    startScan: 'Start IP Scan',
    realdelayBtn: 'RealDelay Test (Xray)',
    realdelayTesting: 'Testing RealDelay with Xray...',
    realdelayDone: 'RealDelay test completed!',
    thRealDelay: 'RealDelay (Proxy)',
    pauseScan: 'Pause',
    resumeScan: 'Resume',
    stopScan: 'Cancel Scan',
    clearTable: 'Clear',
    testedLabel: 'Tested / Total',
    workingLabel: 'Clean IPs Found',
    speedLabel: 'Scan Speed',
    bestPingLabel: 'Best Google Ping',
    resultsTableTitle: 'Working Clean IPs Sorted by Google 204 Latency',
    resultsCount: (n) => `${n.toLocaleString()} items`,
    searchPlaceholder: 'Filter IP or subnet...',
    copyAll: 'Copy IPs',
    export: 'Export',
    exportIps: '📄 Clean IPs List (TXT)',
    exportConfigs: '🔗 Ready Config Links (TXT)',
    exportCsv: '📊 Excel Table (CSV)',
    exportJson: '💾 Full Structure (JSON)',
    thRank: '#',
    thIp: 'IP Address',
    thPrefix: 'Prefix / CIDR',
    thGoogle: 'Google Ping (204) ↓',
    thTcp: 'TCP Latency',
    thTls: 'TLS Handshake',
    thStatus: 'Test Status',
    thActions: 'Actions',
    noResultsTitle: 'Scan has not started yet',
    noResultsDesc: 'Enter your configuration and click "Start IP Scan" to begin.',
    readyText: 'Ready to start scan',
    scanningText: 'Scanning in progress...',
    pausedText: 'Scan paused',
    finishedText: 'Scan completed',
    copiedIp: 'IP copied to clipboard!',
    copiedConfig: 'Ready-to-use config copied!',
    copiedAllIps: (n) => `${n} clean IPs copied to clipboard!`,
    retesting: 'Retesting IP...',
  }
};

// DOM Elements
const el = {
  appTitle: document.getElementById('app-title'),
  appSubtitle: document.getElementById('app-subtitle'),
  asnTitle: document.getElementById('asn-title'),
  btnAs13335: document.getElementById('btn-as13335'),
  btnAs209242: document.getElementById('btn-as209242'),
  customAsnInput: document.getElementById('custom-asn-input'),
  btnFetchBgp: document.getElementById('btn-fetch-bgp'),
  txtFetchBgp: document.getElementById('txt-fetch-bgp'),
  bgpPrefixBadge: document.getElementById('bgp-prefix-badge'),
  btnLangToggle: document.getElementById('btn-lang-toggle'),
  
  titleConfigInput: document.getElementById('title-config-input'),
  configInput: document.getElementById('config-input'),
  protocolBadge: document.getElementById('protocol-badge'),
  tlsBadge: document.getElementById('tls-badge'),
  lblSni: document.getElementById('lbl-sni'),
  valSni: document.getElementById('val-sni'),
  lblPort: document.getElementById('lbl-port'),
  valPort: document.getElementById('val-port'),
  lblTransport: document.getElementById('lbl-transport'),
  valTransport: document.getElementById('val-transport'),
  lblPath: document.getElementById('lbl-path'),
  valPath: document.getElementById('val-path'),

  titleScanParams: document.getElementById('title-scan-params'),
  lblSampleMode: document.getElementById('lbl-sample-mode'),
  selectSampleMode: document.getElementById('select-sample-mode'),
  optRandom: document.getElementById('opt-random'),
  optGateway: document.getElementById('opt-gateway'),
  optStep: document.getElementById('opt-step'),
  optCustom: document.getElementById('opt-custom'),
  lblTargetUrl: document.getElementById('lbl-target-url'),
  selectTargetUrl: document.getElementById('select-target-url'),
  
  lblIpsPerPrefix: document.getElementById('lbl-ips-per-prefix'),
  sliderIpsPerPrefix: document.getElementById('slider-ips-per-prefix'),
  valIpsPerPrefix: document.getElementById('val-ips-per-prefix'),
  lblMaxIps: document.getElementById('lbl-max-ips'),
  sliderMaxIps: document.getElementById('slider-max-ips'),
  valMaxIps: document.getElementById('val-max-ips'),
  lblConcurrency: document.getElementById('lbl-concurrency'),
  sliderConcurrency: document.getElementById('slider-concurrency'),
  valConcurrency: document.getElementById('val-concurrency'),
  lblTimeout: document.getElementById('lbl-timeout'),
  sliderTimeout: document.getElementById('slider-timeout'),
  valTimeout: document.getElementById('val-timeout'),
  customIpsContainer: document.getElementById('custom-ips-container'),
  customIpsInput: document.getElementById('custom-ips-input'),

  btnStart: document.getElementById('btn-start'),
  txtStartScan: document.getElementById('txt-start-scan'),
  btnRealdelay: document.getElementById('btn-realdelay'),
  txtRealdelay: document.getElementById('txt-realdelay'),
  btnPause: document.getElementById('btn-pause'),
  txtPauseScan: document.getElementById('txt-pause-scan'),
  btnStop: document.getElementById('btn-stop'),
  txtStopScan: document.getElementById('txt-stop-scan'),
  btnClear: document.getElementById('btn-clear'),
  txtClearTable: document.getElementById('txt-clear-table'),

  lblStatTested: document.getElementById('lbl-stat-tested'),
  statTested: document.getElementById('stat-tested'),
  lblStatWorking: document.getElementById('lbl-stat-working'),
  statWorking: document.getElementById('stat-working'),
  lblStatSpeed: document.getElementById('lbl-stat-speed'),
  statSpeed: document.getElementById('stat-speed'),
  lblStatPing: document.getElementById('lbl-stat-ping'),
  statBestPing: document.getElementById('stat-best-ping'),

  progressStatusText: document.getElementById('progress-status-text'),
  progressPercentage: document.getElementById('progress-percentage'),
  progressFill: document.getElementById('progress-fill'),

  titleResultsTable: document.getElementById('title-results-table'),
  badgeResultsCount: document.getElementById('badge-results-count'),
  searchFilterInput: document.getElementById('search-filter-input'),
  btnCopyAllIps: document.getElementById('btn-copy-all-ips'),
  txtCopyAll: document.getElementById('txt-copy-all'),
  btnExportDropdown: document.getElementById('btn-export-dropdown'),
  txtExport: document.getElementById('txt-export'),
  exportMenu: document.getElementById('export-menu'),
  expIps: document.getElementById('exp-ips'),
  expConfigs: document.getElementById('exp-configs'),
  expCsv: document.getElementById('exp-csv'),
  expJson: document.getElementById('exp-json'),

  thRank: document.getElementById('th-rank'),
  thIp: document.getElementById('th-ip'),
  thPrefix: document.getElementById('th-prefix'),
  thGoogle: document.getElementById('th-google'),
  thTcp: document.getElementById('th-tcp'),
  thTls: document.getElementById('th-tls'),
  thStatus: document.getElementById('th-status'),
  thActions: document.getElementById('th-actions'),
  resultsTbody: document.getElementById('results-tbody'),
  emptyRow: document.getElementById('empty-row'),
  txtNoResults: document.getElementById('txt-no-results'),
  txtNoResultsDesc: document.getElementById('txt-no-results-desc'),
  toastContainer: document.getElementById('toast-container'),
};

// Toast notification helper
function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `<span>${message}</span>`;
  el.toastContainer.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    setTimeout(() => toast.remove(), 300);
  }, 2800);
}

// Language switch
function setLanguage(lang) {
  state.lang = lang;
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === 'fa' ? 'rtl' : 'ltr';
  el.btnLangToggle.querySelector('.lang-text').innerText = lang === 'fa' ? 'EN' : 'FA';

  const t = i18n[lang];
  el.btnAs13335.innerText = lang === 'fa' ? 'AS13335 (اصلی)' : 'AS13335 (Main)';
  el.btnAs209242.innerText = lang === 'fa' ? 'AS209242 (Inc)' : 'AS209242 (Inc)';
  el.customAsnInput.placeholder = lang === 'fa' ? 'ASN دلخواه (مثلا 13335)' : 'Custom ASN (e.g. 13335)';
  el.appTitle.innerText = t.appTitle;
  el.appSubtitle.innerText = t.appSubtitle;
  el.asnTitle.innerText = t.asnTitle;
  el.txtFetchBgp.innerText = t.fetchBgp;
  el.titleConfigInput.innerText = t.configInputTitle;
  el.configInput.placeholder = t.configPlaceholder;
  el.lblSni.innerText = t.sniLabel;
  el.lblPort.innerText = t.portLabel;
  el.lblTransport.innerText = t.transportLabel;
  el.lblPath.innerText = t.pathLabel;
  el.titleScanParams.innerText = t.scanParamsTitle;
  el.lblSampleMode.innerText = t.sampleModeLabel;
  el.optRandom.innerText = t.optRandom;
  el.optGateway.innerText = t.optGateway;
  el.optStep.innerText = t.optStep;
  el.optCustom.innerText = t.optCustom;
  el.lblTargetUrl.innerText = t.targetUrlLabel;
  el.lblIpsPerPrefix.innerText = t.ipsPerPrefixLabel;
  el.lblMaxIps.innerText = t.maxIpsLabel;
  el.lblConcurrency.innerText = t.concurrencyLabel;
  el.lblTimeout.innerText = t.timeoutLabel;
  el.valTimeout.innerText = `${el.sliderTimeout.value} ${t.seconds}`;
  el.txtStartScan.innerText = t.startScan;
  el.txtRealdelay.innerText = t.realdelayBtn;
  const thRealdelay = document.getElementById('th-realdelay');
  if (thRealdelay) thRealdelay.innerText = t.thRealDelay;
  el.txtPauseScan.innerText = state.isPaused ? t.resumeScan : t.pauseScan;
  el.txtStopScan.innerText = t.stopScan;
  el.txtClearTable.innerText = t.clearTable;
  el.lblStatTested.innerText = t.testedLabel;
  el.lblStatWorking.innerText = t.workingLabel;
  el.lblStatSpeed.innerText = t.speedLabel;
  el.lblStatPing.innerText = t.bestPingLabel;
  el.titleResultsTable.innerText = t.resultsTableTitle;
  el.searchFilterInput.placeholder = t.searchPlaceholder;
  el.txtCopyAll.innerText = t.copyAll;
  el.txtExport.innerText = t.export;
  el.expIps.innerText = t.exportIps;
  el.expConfigs.innerText = t.exportConfigs;
  el.expCsv.innerText = t.exportCsv;
  el.expJson.innerText = t.exportJson;
  el.thIp.innerText = t.thIp;
  el.thPrefix.innerText = t.thPrefix;
  el.thGoogle.innerText = t.thGoogle;
  el.thTcp.innerText = t.thTcp;
  el.thTls.innerText = t.thTls;
  el.thStatus.innerText = t.thStatus;
  el.thActions.innerText = t.thActions;
  el.txtNoResults.innerText = t.noResultsTitle;
  el.txtNoResultsDesc.innerText = t.noResultsDesc;

  if (state.totalPrefixes > 0) {
    el.bgpPrefixBadge.innerText = t.prefixesLoaded(state.totalPrefixes);
  }
}

// BGP Prefix fetcher
async function fetchBgpPrefixes(asn) {
  el.txtFetchBgp.innerText = '...';
  el.bgpPrefixBadge.innerText = 'Fetching BGP...';
  try {
    const res = await fetch('/api/fetch-prefixes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ asn })
    });
    const data = await res.json();
    if (data.status === 'success' && data.data) {
      state.totalPrefixes = (data.data.total_v4 || 0) + (data.data.total_v6 || 0);
      el.bgpPrefixBadge.innerText = i18n[state.lang].prefixesLoaded(state.totalPrefixes);
      showToast(`BGP prefixes loaded for ${data.data.asn}: ${data.data.total_v4} IPv4 ranges`, 'success');
    }
  } catch (err) {
    console.error('Failed to fetch BGP prefixes:', err);
    el.bgpPrefixBadge.innerText = 'Fallback CIDR';
  } finally {
    el.txtFetchBgp.innerText = i18n[state.lang].fetchBgp;
  }
}

// Config parser debounce
let parseTimeout = null;
function handleConfigInput() {
  clearTimeout(parseTimeout);
  parseTimeout = setTimeout(async () => {
    const text = el.configInput.value.trim();
    if (!text) {
      // Clean reset of badges and chips
      el.protocolBadge.innerText = 'VLESS';
      el.tlsBadge.innerText = 'TLS: فعال';
      el.valSni.innerText = 'auto';
      el.valPort.innerText = '443';
      el.valTransport.innerText = 'ws';
      el.valPath.innerText = '/';
      return;
    }
    try {
      const res = await fetch('/api/parse-config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ config: text })
      });
      const data = await res.json();
      if (data.status === 'success' && data.parsed) {
        const p = data.parsed;
        el.protocolBadge.innerText = (p.protocol || 'VLESS').toUpperCase();
        el.tlsBadge.innerText = p.security ? `TLS: ${p.security}` : 'No TLS';
        el.valSni.innerText = p.sni || p.host || p.address || 'auto';
        el.valPort.innerText = p.port || 443;
        el.valTransport.innerText = p.transport || 'ws';
        el.valPath.innerText = p.path || '/';
      }
    } catch (e) {
      console.error('Parse config error:', e);
    }
  }, 300);
}

// SSE real-time stream consumer
function initSSE() {
  if (state.eventSource) {
    state.eventSource.close();
  }

  state.eventSource = new EventSource('/api/stream');

  state.eventSource.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      handleServerEvent(msg);
    } catch (e) {
      // Keepalive message
    }
  };

  state.eventSource.onerror = () => {
    setTimeout(initSSE, 3000);
  };
}

function handleServerEvent(msg) {
  const { event, data } = msg;

  if (event === 'scan_started') {
    state.isRunning = true;
    state.isPaused = false;
    state.totalCount = data.total || 0;
    state.testedCount = 0;
    updateControlsState();
    el.progressStatusText.innerText = i18n[state.lang].scanningText;
    showToast(`${i18n[state.lang].scanningText} (${state.totalCount} IPs)`, 'info');
  } else if (event === 'working_ip_found') {
    addWorkingResult(data);
  } else if (event === 'realdelay_started') {
    showToast(i18n[state.lang].realdelayTesting, 'info');
    el.progressStatusText.innerText = i18n[state.lang].realdelayTesting;
  } else if (event === 'realdelay_result') {
    const existing = state.workingResults.find(r => r.ip === data.ip);
    if (existing) {
      existing.real_delay_ms = data.realdelay_ms;
      if (data.real_status && data.real_status.includes('OK')) {
        existing.google_status = data.real_status;
      }
      renderTable();
    }
  } else if (event === 'realdelay_finished') {
    showToast(i18n[state.lang].realdelayDone, 'success');
    el.progressStatusText.innerText = i18n[state.lang].realdelayDone;
    // Re-sort by RealDelay
    state.workingResults.sort((a, b) => {
      const dA = a.real_delay_ms > 0 ? a.real_delay_ms : 99999;
      const dB = b.real_delay_ms > 0 ? b.real_delay_ms : 99999;
      return dA - dB;
    });
    renderTable();
  } else if (event === 'progress') {
    state.testedCount = data.tested || 0;
    state.speed = data.speed || 0;
    updateProgressUI();
  } else if (event === 'status_change') {
    if (data.state === 'paused') {
      state.isPaused = true;
      el.progressStatusText.innerText = i18n[state.lang].pausedText;
    } else if (data.state === 'running') {
      state.isPaused = false;
      el.progressStatusText.innerText = i18n[state.lang].scanningText;
    } else if (data.state === 'stopped') {
      state.isRunning = false;
      state.isPaused = false;
      el.progressStatusText.innerText = i18n[state.lang].readyText;
    }
    updateControlsState();
  } else if (event === 'scan_finished') {
    state.isRunning = false;
    state.isPaused = false;
    updateControlsState();
    el.progressStatusText.innerText = i18n[state.lang].finishedText;
    showToast(`${i18n[state.lang].finishedText} - ${state.workingResults.length} clean IPs found!`, 'success');
  }
}

// Add working result and insert into sorted order based on Google 204 Latency
function addWorkingResult(result) {
  const existingIdx = state.workingResults.findIndex(r => r.ip === result.ip);
  if (existingIdx >= 0) {
    state.workingResults[existingIdx] = result;
  } else {
    // Binary insert into sorted array by Google Latency (ascending)
    const lat = result.google_latency_ms > 0 ? result.google_latency_ms : 99999;
    let low = 0;
    let high = state.workingResults.length;
    while (low < high) {
      const mid = (low + high) >>> 1;
      const midLat = state.workingResults[mid].google_latency_ms > 0 ? state.workingResults[mid].google_latency_ms : 99999;
      if (midLat < lat) low = mid + 1;
      else high = mid;
    }
    state.workingResults.splice(low, 0, result);
  }

  // Update best ping stat
  if (result.google_latency_ms > 0 && result.google_latency_ms < state.bestPing) {
    state.bestPing = result.google_latency_ms;
    el.statBestPing.innerText = `${state.bestPing.toFixed(0)} ms`;
  }

  renderTable();
}

// Render Table with debounced DOM update
let renderTableTimer = null;
function renderTable() {
  clearTimeout(renderTableTimer);
  renderTableTimer = setTimeout(() => {
    const filter = state.searchFilter.toLowerCase();
    const filtered = state.workingResults.filter(r => {
      if (!filter) return true;
      return (r.ip && r.ip.toLowerCase().includes(filter)) ||
             (r.prefix && r.prefix.toLowerCase().includes(filter)) ||
             (r.google_status && r.google_status.toLowerCase().includes(filter));
    });

    el.badgeResultsCount.innerText = i18n[state.lang].resultsCount(filtered.length);
    el.statWorking.innerText = state.workingResults.length;

    if (filtered.length === 0) {
      el.emptyRow.style.display = '';
      // Remove other rows
      const rows = el.resultsTbody.querySelectorAll('.result-row');
      rows.forEach(r => r.remove());
      return;
    }

    el.emptyRow.style.display = 'none';

    // Build rows HTML
    const html = filtered.map((r, idx) => {
      const rank = idx + 1;
      const realDelay = r.real_delay_ms > 0 ? `${r.real_delay_ms.toFixed(0)} ms` : '--';
      const realDelayClass = r.real_delay_ms > 0 ? 'lat-cyan' : 'lat-dim';

      const googleLat = r.google_latency_ms ? `${r.google_latency_ms.toFixed(0)} ms` : '--';
      let latClass = 'lat-fast';
      if (r.google_latency_ms > 350) latClass = 'lat-slow';
      else if (r.google_latency_ms > 180) latClass = 'lat-medium';

      const tcpLat = r.tcp_latency_ms ? `${r.tcp_latency_ms.toFixed(0)} ms` : '--';
      const tlsLat = r.tls_latency_ms ? `${r.tls_latency_ms.toFixed(0)} ms` : '--';

      return `
        <tr class="result-row" data-ip="${r.ip}">
          <td class="td-rank">${rank}</td>
          <td class="td-ip">
            <span>${r.ip}</span>
            <button class="btn-icon-action btn-copy-ip" data-ip="${r.ip}" title="کپی آی‌پی">
              <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
            </button>
          </td>
          <td class="td-prefix">${r.prefix || 'N/A'}</td>
          <td><span class="lat-pill ${realDelayClass}">${realDelay}</span></td>
          <td><span class="lat-pill ${latClass}">${googleLat}</span></td>
          <td><span class="lat-dim">${tcpLat}</span></td>
          <td><span class="lat-dim">${tlsLat}</span></td>
          <td><span class="status-badge status-badge-green">${r.google_status || '204 OK'}</span></td>
          <td class="th-actions">
            <div class="row-actions">
              <button class="btn-icon-action btn-copy-link" data-link="${encodeURIComponent(r.modified_link || '')}" title="کپی کانفیگ با این آی‌پی">
                <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
              </button>
              <button class="btn-icon-action btn-retest" data-ip="${r.ip}" title="تست مجدد">
                <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none"><path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/><path d="M16 21h5v-5"/></svg>
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join('');

    // Update table
    el.resultsTbody.innerHTML = html;
  }, 60);
}

// Update live progress and metrics
function updateProgressUI() {
  const percent = state.totalCount > 0 ? Math.min(100, Math.round((state.testedCount / state.totalCount) * 100)) : 0;
  el.progressPercentage.innerText = `${percent}%`;
  el.progressFill.style.width = `${percent}%`;

  el.statTested.innerText = `${state.testedCount.toLocaleString()} / ${state.totalCount.toLocaleString()}`;
  el.statSpeed.innerText = `${state.speed} IP/s`;
}

// Update button enabled/disabled states
function updateControlsState() {
  el.btnStart.disabled = state.isRunning && !state.isPaused;
  el.btnPause.disabled = !state.isRunning;
  el.btnStop.disabled = !state.isRunning;

  if (state.isPaused) {
    el.txtPauseScan.innerText = i18n[state.lang].resumeScan;
  } else {
    el.txtPauseScan.innerText = i18n[state.lang].pauseScan;
  }
}

// Setup Event Listeners
function setupEvents() {
  // ASN buttons
  el.btnAs13335.addEventListener('click', () => {
    el.btnAs13335.classList.add('active');
    el.btnAs209242.classList.remove('active');
    el.customAsnInput.value = '13335';
    state.currentAsn = '13335';
    fetchBgpPrefixes('13335');
  });

  el.btnAs209242.addEventListener('click', () => {
    el.btnAs209242.classList.add('active');
    el.btnAs13335.classList.remove('active');
    el.customAsnInput.value = '209242';
    state.currentAsn = '209242';
    fetchBgpPrefixes('209242');
  });

  el.btnFetchBgp.addEventListener('click', () => {
    const asn = el.customAsnInput.value.trim() || '13335';
    state.currentAsn = asn;
    fetchBgpPrefixes(asn);
  });

  // Language toggle
  el.btnLangToggle.addEventListener('click', () => {
    const nextLang = state.lang === 'fa' ? 'en' : 'fa';
    setLanguage(nextLang);
  });

  // Config input
  el.configInput.addEventListener('input', handleConfigInput);

  // Sliders
  el.sliderIpsPerPrefix.addEventListener('input', (e) => {
    el.valIpsPerPrefix.innerText = e.target.value;
  });

  el.sliderMaxIps.addEventListener('input', (e) => {
    el.valMaxIps.innerText = e.target.value;
  });

  el.sliderConcurrency.addEventListener('input', (e) => {
    el.valConcurrency.innerText = e.target.value;
  });

  el.sliderTimeout.addEventListener('input', (e) => {
    el.valTimeout.innerText = `${e.target.value} ${i18n[state.lang].seconds}`;
  });

  // Sample mode select
  el.selectSampleMode.addEventListener('change', (e) => {
    if (e.target.value === 'custom') {
      el.customIpsContainer.classList.remove('hidden');
    } else {
      el.customIpsContainer.classList.add('hidden');
    }
  });

  // Search filter
  el.searchFilterInput.addEventListener('input', (e) => {
    state.searchFilter = e.target.value.trim();
    renderTable();
  });

  // Start Scan
  el.btnStart.addEventListener('click', async () => {
    const rawConfig = el.configInput.value.trim();
    const sampleMode = el.selectSampleMode.value;
    const ipsPerPrefix = parseInt(el.sliderIpsPerPrefix.value);
    const maxTotalIps = parseInt(el.sliderMaxIps.value);
    const concurrency = parseInt(el.sliderConcurrency.value);
    const timeoutSec = parseFloat(el.sliderTimeout.value);
    const targetUrl = el.selectTargetUrl.value;
    const customIpsText = el.customIpsInput.value.trim();
    const customIps = customIpsText ? customIpsText.split('\n').map(s => s.trim()).filter(Boolean) : [];

    try {
      const res = await fetch('/api/start-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          asn: state.currentAsn,
          config: rawConfig,
          sample_mode: sampleMode,
          ips_per_prefix: ipsPerPrefix,
          max_total_ips: maxTotalIps,
          concurrency: concurrency,
          timeout_sec: timeoutSec,
          target_url: targetUrl,
          custom_ips: customIps
        })
      });
      const data = await res.json();
      if (data.status === 'success') {
        state.isRunning = true;
        state.isPaused = false;
        updateControlsState();
      } else {
        showToast(`Error: ${data.message}`, 'error');
      }
    } catch (e) {
      showToast(`Network error: ${e}`, 'error');
    }
  });

  // RealDelay Test Button
  el.btnRealdelay.addEventListener('click', async () => {
    if (state.workingResults.length === 0) {
      showToast('ابتدا اسکن را اجرا کنید تا آی‌پی‌های سالم پیدا شوند', 'error');
      return;
    }
    const rawConfig = el.configInput.value.trim();
    showToast(i18n[state.lang].realdelayTesting, 'info');
    try {
      const res = await fetch('/api/start-realdelay-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          config: rawConfig,
          concurrency: 10,
          timeout_sec: 4.0
        })
      });
      const data = await res.json();
      if (data.status === 'success') {
        showToast(data.message, 'success');
      } else {
        showToast(`خطا: ${data.message}`, 'error');
      }
    } catch (err) {
      showToast(`خطای شبکه: ${err}`, 'error');
    }
  });

  // Pause / Resume Scan
  el.btnPause.addEventListener('click', async () => {
    if (state.isPaused) {
      await fetch('/api/resume-scan', { method: 'POST' });
    } else {
      await fetch('/api/pause-scan', { method: 'POST' });
    }
  });

  // Stop Scan
  el.btnStop.addEventListener('click', async () => {
    await fetch('/api/stop-scan', { method: 'POST' });
  });

  // Clear Results & Config
  el.btnClear.addEventListener('click', () => {
    el.configInput.value = '';
    handleConfigInput();
    state.workingResults = [];
    state.testedCount = 0;
    state.totalCount = 0;
    state.bestPing = Infinity;
    el.statBestPing.innerText = '-- ms';
    updateProgressUI();
    renderTable();
    showToast(i18n[state.lang].clearTable, 'info');
  });

  // Copy all Clean IPs
  el.btnCopyAllIps.addEventListener('click', () => {
    if (state.workingResults.length === 0) {
      showToast('No clean IPs found yet!', 'error');
      return;
    }
    const ipList = state.workingResults.map(r => r.ip).join('\n');
    navigator.clipboard.writeText(ipList).then(() => {
      showToast(i18n[state.lang].copiedAllIps(state.workingResults.length), 'success');
    });
  });

  // Export dropdown
  el.btnExportDropdown.addEventListener('click', (e) => {
    e.stopPropagation();
    el.exportMenu.classList.toggle('hidden');
  });

  document.addEventListener('click', () => {
    el.exportMenu.classList.add('hidden');
  });

  el.exportMenu.querySelectorAll('.export-opt').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const fmt = e.target.getAttribute('data-fmt');
      try {
        const res = await fetch('/api/export', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ format: fmt, results: state.workingResults })
        });
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `cloudflare_clean_${fmt}.${fmt === 'links' || fmt === 'ips' ? 'txt' : fmt}`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        showToast(`Exported as ${fmt.toUpperCase()}`, 'success');
      } catch (err) {
        showToast('Export failed', 'error');
      }
    });
  });

  // Table row actions delegation (Copy IP, Copy Link, Retest)
  el.resultsTbody.addEventListener('click', async (e) => {
    const copyIpBtn = e.target.closest('.btn-copy-ip');
    if (copyIpBtn) {
      const ip = copyIpBtn.getAttribute('data-ip');
      navigator.clipboard.writeText(ip).then(() => {
        showToast(i18n[state.lang].copiedIp, 'success');
      });
      return;
    }

    const copyLinkBtn = e.target.closest('.btn-copy-link');
    if (copyLinkBtn) {
      const rawLink = decodeURIComponent(copyLinkBtn.getAttribute('data-link') || '');
      if (rawLink) {
        navigator.clipboard.writeText(rawLink).then(() => {
          showToast(i18n[state.lang].copiedConfig, 'success');
        });
      } else {
        showToast('No link generated', 'error');
      }
      return;
    }

    const retestBtn = e.target.closest('.btn-retest');
    if (retestBtn) {
      const ip = retestBtn.getAttribute('data-ip');
      showToast(`${i18n[state.lang].retesting} ${ip}`, 'info');
      try {
        const res = await fetch('/api/test-single', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip, config: el.configInput.value.trim() })
        });
        const data = await res.json();
        if (data.status === 'success' && data.result) {
          addWorkingResult(data.result);
          showToast(`Retest ${ip}: ${data.result.google_status} (${data.result.google_latency_ms}ms)`, 'success');
        }
      } catch (err) {
        showToast(`Retest failed: ${err}`, 'error');
      }
    }
  });
}

// Initialization
document.addEventListener('DOMContentLoaded', () => {
  setLanguage('fa');
  setupEvents();
  initSSE();
  fetchBgpPrefixes('13335');
});
