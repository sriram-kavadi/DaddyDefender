(function () {
  'use strict';

  var HISTORY_KEY = 'threatcheck.history.v1';
  var HISTORY_MAX = 10;
  var PREVIEW_LEN = 80;

  // Determine API Base URL:
  // 1. If explicitly set via window.THREATCHECK_API_BASE, use that
  // 2. If running locally (localhost/127.0.0.1) on a frontend dev port (e.g. 5500), connect to local backend port 8000
  // 3. Otherwise (production deployment on Vercel, or served on port 8000), use relative ''
  var isLocalDev = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') &&
                   window.location.port !== '8000' && window.location.port !== '8001';
  var API_BASE = window.THREATCHECK_API_BASE || (isLocalDev ? 'http://localhost:8000' : '');

  var backendOnline = false;
  var activeHistoryTab = 'local'; // 'local' or 'server'
  var cachedServerScans = [];

  var EXAMPLES = {
    link: 'http://paypa1-secure-login.xyz/verify?session=48213',
    scam: 'URGENT: Your bank account has been suspended due to unusual activity. Verify your identity within 24 hours or your account will be closed. Click here: http://secure-hdfc-update.top/login and enter your OTP and card number. Do not tell anyone.',
    safe: 'Hi, the meeting notes are at https://docs.example.org/notes. See you at 3.'
  };

  // DOM Elements
  var form = document.getElementById('form');
  var input = document.getElementById('input');
  var btnSubmit = document.getElementById('btn-submit');
  var errorBox = document.getElementById('input-error');
  var resultBox = document.getElementById('result');
  var loadingSpinner = document.getElementById('loading-spinner');
  var loadingMsg = document.getElementById('loading-msg');
  var statusDot = document.getElementById('status-dot');
  var statusLabel = document.getElementById('status-label');
  var statsBar = document.getElementById('stats-bar');
  var statTotal = document.getElementById('stat-total');
  var statAvg = document.getElementById('stat-avg');
  var statThreats = document.getElementById('stat-threats');
  var historySection = document.getElementById('history-section');
  var historyList = document.getElementById('history-list');
  var historyHint = document.getElementById('history-hint');
  var tabLocal = document.getElementById('tab-local');
  var tabServer = document.getElementById('tab-server');
  var serverCount = document.getElementById('server-count');
  var clearHistoryBtn = document.getElementById('clear-history');

  /* Safe DOM builder */
  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }

  function levelWord(level) {
    if (!level) return 'Low';
    return level.charAt(0).toUpperCase() + level.slice(1).toLowerCase();
  }

  /* ──────────────────────────────────────────────────────────────────
     Backend Health & Connectivity
     ────────────────────────────────────────────────────────────────── */
  async function checkBackendHealth() {
    if (statusDot) {
      statusDot.className = 'status-dot checking';
      statusLabel.textContent = 'Connecting...';
    }

    try {
      var res = await fetch(API_BASE + '/api/health', { method: 'GET', credentials: 'omit' });
      if (res.ok) {
        var data = await res.json();
        backendOnline = true;
        statusDot.className = 'status-dot online';
        var providers = Object.keys(data.providers || {}).length;
        statusLabel.textContent = 'Backend Engine Active (' + providers + ' intel providers)';
        loadStats();
        loadServerHistoryCount();
        return true;
      }
    } catch (e) {
      // Backend not running
    }

    backendOnline = false;
    if (statusDot) {
      statusDot.className = 'status-dot offline';
      statusLabel.textContent = 'Local Browser Engine (Offline)';
    }
    return false;
  }

  /* ──────────────────────────────────────────────────────────────────
     Statistics
     ────────────────────────────────────────────────────────────────── */
  async function loadStats() {
    if (!backendOnline || !statsBar) return;
    try {
      var res = await fetch(API_BASE + '/api/scans/stats');
      if (res.ok) {
        var data = await res.json();
        if (data.total_scans > 0) {
          statsBar.hidden = false;
          statTotal.textContent = String(data.total_scans);
          statAvg.textContent = String(data.average_score) + ' / 100';
          var threats = (data.by_level.high || 0) + (data.by_level.critical || 0);
          statThreats.textContent = String(threats);
        }
      }
    } catch (e) {
      // Silently ignore stats fetch failure
    }
  }

  /* ──────────────────────────────────────────────────────────────────
     Render Results
     ────────────────────────────────────────────────────────────────── */
  function renderUnifiedResult(result, isBackend) {
    resultBox.textContent = '';
    var level = (result.risk_level || result.level || 'low').toLowerCase();
    resultBox.setAttribute('data-level', level);

    // Classification Banner
    var classification = result.classification || (levelWord(level) + ' Risk');
    var banner = el('span', 'classification-banner', classification);
    banner.setAttribute('data-level', level);
    resultBox.appendChild(banner);

    // Engine source note
    if (!isBackend) {
      var fallbackNotice = el('p', 'hint', 'Analyzed with local browser heuristics (Backend offline)');
      fallbackNotice.style.margin = '0 0 0.5rem';
      resultBox.appendChild(fallbackNotice);
    }

    // Header: Level name and numeric score
    var head = el('div', 'result-head');
    var label = result.label || (levelWord(level) + ' risk');
    head.appendChild(el('h2', 'level-name', label));
    var scoreSpan = el('span', 'score');
    var scoreVal = result.risk_score != null ? result.risk_score : result.score;
    scoreSpan.appendChild(el('strong', null, String(scoreVal)));
    scoreSpan.appendChild(document.createTextNode(' out of 100'));
    head.appendChild(scoreSpan);
    resultBox.appendChild(head);

    // Meter Bar
    var meter = el('div', 'meter');
    meter.setAttribute('role', 'meter');
    meter.setAttribute('aria-valuemin', '0');
    meter.setAttribute('aria-valuemax', '100');
    meter.setAttribute('aria-valuenow', String(scoreVal));
    meter.setAttribute('aria-label', 'Risk score');
    var bar = el('span');
    bar.style.width = Math.max(scoreVal, 2) + '%';
    meter.appendChild(bar);
    resultBox.appendChild(meter);

    // Explanation / Summary
    var summaryText = result.explanation || result.summary;
    if (summaryText) {
      resultBox.appendChild(el('p', 'summary', summaryText));
    }

    // Threat Intelligence Providers Section (if backend returned provider results)
    if (result.provider_results && result.provider_results.length) {
      resultBox.appendChild(el('h3', null, 'Threat Intelligence Correlation'));
      var grid = el('div', 'provider-grid');
      result.provider_results.forEach(function (pr) {
        var card = el('div', 'provider-card');
        var cardHead = el('div', 'provider-card-head');
        cardHead.appendChild(el('span', null, pr.provider));

        var statusClass = 'not-found';
        var statusText = pr.status;
        if (pr.result && pr.result.malicious > 0) {
          statusClass = 'malicious';
          statusText = pr.result.malicious + ' engines flagged';
        } else if (pr.result && (pr.result.threat || pr.result.threat_type)) {
          statusClass = 'malicious';
          statusText = 'Flagged';
        } else if (pr.status === 'clean' || pr.status === 'not found' || pr.status === 'no results') {
          statusClass = 'clean';
          statusText = 'Clean / No match';
        } else if (pr.status === 'not configured') {
          statusClass = 'not-found';
          statusText = 'Unconfigured';
        } else if (pr.status === 'authentication error') {
          statusClass = 'error';
          statusText = 'Key Required';
        } else if (pr.status === 'error') {
          statusClass = 'error';
          statusText = 'Notice';
        }
        var badge = el('span', 'provider-status-badge ' + statusClass, statusText);
        cardHead.appendChild(badge);
        card.appendChild(cardHead);

        var detailText = pr.error || (pr.result && pr.result.message) || 'Checked against live database.';
        card.appendChild(el('p', 'provider-card-detail', detailText));
        grid.appendChild(card);
      });
      resultBox.appendChild(grid);
    }

    // Findings / Red flags
    resultBox.appendChild(el('h3', null, 'Why this rating'));
    var findings = result.findings || result.reasons || [];
    if (findings.length) {
      var ul = el('ul', 'reasons');
      findings.forEach(function (f) {
        var li = el('li');
        var top = el('div', 'reason-top');
        var titleContainer = el('div', null);

        // Indicator title
        var titleText = f.title || f.indicator;
        titleContainer.appendChild(el('span', null, titleText));

        // Source & Severity Badges
        var tags = el('div', 'reason-tags');
        if (f.source) {
          var isIntel = f.source === 'threat-intelligence';
          tags.appendChild(el('span', 'badge badge-source' + (isIntel ? ' intel' : ''), isIntel ? 'Threat Intel' : 'Heuristic'));
        }
        if (f.severity) {
          tags.appendChild(el('span', 'badge badge-severity ' + f.severity.toLowerCase(), f.severity));
        }
        titleContainer.appendChild(tags);
        top.appendChild(titleContainer);

        var ptsVal = f.points != null ? f.points : 0;
        top.appendChild(el('span', 'pts', '+' + ptsVal));
        li.appendChild(top);

        var detailText = f.explanation || f.detail;
        if (detailText) {
          li.appendChild(el('p', null, detailText));
        }

        // Evidence code snippet if provided
        if (f.evidence) {
          li.appendChild(el('div', 'reason-evidence', 'Evidence: ' + f.evidence));
        }

        // Actionable tip if provided
        if (f.tip) {
          li.appendChild(el('p', 'reason-tip', 'Tip: ' + f.tip));
        }

        ul.appendChild(li);
      });
      resultBox.appendChild(ul);
    } else {
      resultBox.appendChild(el('p', 'none',
        (result.scan_type === 'message' || result.type === 'message')
          ? 'None of the message wording rules matched.'
          : 'None of the link rules matched.'));
    }

    // Links found in message
    var links = result.links || [];
    if (links.length) {
      resultBox.appendChild(el('h3', null, links.length === 1 ? 'Link found in the message' : 'Links found in the message'));
      links.forEach(function (link) {
        var linkLevel = (link.risk_level || link.level || 'low').toLowerCase();
        var linkScore = link.risk_score != null ? link.risk_score : link.score;
        var block = el('div', 'link-block');
        block.setAttribute('data-level', linkLevel);
        block.appendChild(el('p', 'link-url', link.url));
        var line = el('p');
        line.appendChild(el('span', 'link-level', levelWord(linkLevel) + ' risk'));
        line.appendChild(document.createTextNode(' (' + linkScore + ' out of 100)'));
        block.appendChild(line);

        var lFindings = link.findings || link.reasons || [];
        if (lFindings.length) {
          var lUl = el('ul', 'reasons');
          lFindings.forEach(function (lf) {
            var lLi = el('li');
            var lTop = el('div', 'reason-top');
            lTop.appendChild(el('span', null, lf.title || lf.indicator));
            lTop.appendChild(el('span', 'pts', '+' + (lf.points != null ? lf.points : 0)));
            lLi.appendChild(lTop);
            var lDetail = lf.explanation || lf.detail;
            if (lDetail) lLi.appendChild(el('p', null, lDetail));
            lUl.appendChild(lLi);
          });
          block.appendChild(lUl);
        } else {
          block.appendChild(el('p', 'none', 'No red flags matched for this link.'));
        }
        resultBox.appendChild(block);
      });
    }

    // Recommendations
    resultBox.appendChild(el('h3', null, 'What to do'));
    var recs = el('ul', 'recs');
    (result.recommendations || []).forEach(function (t) {
      recs.appendChild(el('li', null, t));
    });
    resultBox.appendChild(recs);

    // Limitations
    var limits = result.limitations || result.limits;
    if (limits) {
      resultBox.appendChild(el('p', 'limits', limits));
    }

    // Scan Metadata bar
    if (result.scan_id) {
      var metaBar = el('div', 'scan-meta');
      var idSpan = el('span', 'scan-meta-id', 'Scan ID: ' + result.scan_id);
      metaBar.appendChild(idSpan);

      if (result.timestamp) {
        var dateSpan = el('span', null, new Date(result.timestamp).toLocaleString());
        metaBar.appendChild(dateSpan);
      }

      var copyBtn = el('button', 'btn btn-small', 'Copy Scan ID');
      copyBtn.type = 'button';
      copyBtn.addEventListener('click', function () {
        if (navigator.clipboard) {
          navigator.clipboard.writeText(result.scan_id);
          copyBtn.textContent = 'Copied!';
          setTimeout(function () { copyBtn.textContent = 'Copy Scan ID'; }, 2000);
        }
      });
      metaBar.appendChild(copyBtn);
      resultBox.appendChild(metaBar);
    }

    resultBox.hidden = false;
    resultBox.focus({ preventScroll: true });
    resultBox.scrollIntoView({ block: 'start' });
  }

  function showError(message) {
    errorBox.textContent = message;
    errorBox.hidden = false;
    resultBox.hidden = true;
  }

  function clearError() {
    errorBox.textContent = '';
    errorBox.hidden = true;
  }

  function showLoading(show, message) {
    if (loadingSpinner) {
      if (show) {
        loadingSpinner.removeAttribute('hidden');
        loadingSpinner.style.display = 'flex';
      } else {
        loadingSpinner.setAttribute('hidden', '');
        loadingSpinner.style.display = 'none';
      }
      if (message && loadingMsg) loadingMsg.textContent = message;
    }
    if (btnSubmit) {
      btnSubmit.disabled = show;
      btnSubmit.textContent = show ? 'Analyzing...' : 'Analyze';
    }
  }

  /* ──────────────────────────────────────────────────────────────────
     Analysis Workflow (Backend with Client-side Fallback)
     ────────────────────────────────────────────────────────────────── */
  function isProbableSingleUrl(text) {
    var trimmed = text.trim();
    if (trimmed.includes(' ') || trimmed.includes('\n')) return false;
    if (/^https?:\/\//i.test(trimmed)) return true;
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(\/.*)?$/i.test(trimmed)) return true;
    return false;
  }

  async function performAnalysis(text) {
    clearError();
    var trimmed = text.trim();
    if (!trimmed) {
      showError('Paste a link or a message first.');
      input.focus();
      return;
    }

    showLoading(true, 'Analyzing indicators and querying threat intelligence...');

    // Try backend if online (or attempt check)
    var useUrl = isProbableSingleUrl(trimmed);
    var endpoint = useUrl ? '/api/analyze/url' : '/api/analyze/message';
    var payload = useUrl ? { url: trimmed } : { message: trimmed };

    var backendSucceeded = false;
    var scanResult = null;

    try {
      var res = await fetch(API_BASE + endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (res.ok) {
        scanResult = await res.json();
        backendSucceeded = true;
        backendOnline = true;
        if (statusDot) {
          statusDot.className = 'status-dot online';
          statusLabel.textContent = 'Backend Engine Active';
        }
      } else if (res.status === 400 && useUrl) {
        // If /api/analyze/url rejected as invalid URL, retry as message
        var msgRes = await fetch(API_BASE + '/api/analyze/message', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: trimmed }),
        });
        if (msgRes.ok) {
          scanResult = await msgRes.json();
          backendSucceeded = true;
        } else {
          var errData = await res.json().catch(function () { return {}; });
          showError(errData.detail || 'Analysis request rejected by server.');
          showLoading(false);
          return;
        }
      } else {
        var errObj = await res.json().catch(function () { return {}; });
        showError(errObj.detail || 'Analysis request failed.');
        showLoading(false);
        return;
      }
    } catch (networkErr) {
      // Backend unreachable: fallback to local client-side analysis
      console.warn('Backend unavailable, falling back to local analyzer.js:', networkErr);
      backendOnline = false;
      if (statusDot) {
        statusDot.className = 'status-dot offline';
        statusLabel.textContent = 'Local Browser Engine (Offline)';
      }
    }

    showLoading(false);

    if (backendSucceeded && scanResult) {
      renderUnifiedResult(scanResult, true);
      addLocalHistory(trimmed, scanResult);
      loadStats();
      loadServerHistoryCount();
      if (activeHistoryTab === 'server') {
        renderServerHistory();
      }
    } else {
      // Local client-side fallback
      var localResult = window.ThreatCheck.analyze(trimmed);
      if (localResult.error === 'empty') {
        showError('Paste a link or a message first.');
        input.focus();
        return;
      }
      if (localResult.error === 'invalid-url') {
        showError('That does not look like a valid web address. Paste the full link, or paste the message text.');
        input.focus();
        return;
      }
      renderUnifiedResult(localResult, false);
      addLocalHistory(trimmed, localResult);
    }
  }

  /* ──────────────────────────────────────────────────────────────────
     History Management (Local Storage + SQLite Server)
     ────────────────────────────────────────────────────────────────── */
  function loadLocalHistory() {
    try {
      var raw = window.localStorage.getItem(HISTORY_KEY);
      var parsed = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed : [];
    } catch (e) {
      return [];
    }
  }

  function saveLocalHistory(list) {
    try { window.localStorage.setItem(HISTORY_KEY, JSON.stringify(list)); } catch (e) {}
  }

  function addLocalHistory(text, result) {
    var list = loadLocalHistory();
    var preview = text.replace(/\s+/g, ' ').trim();
    if (preview.length > PREVIEW_LEN) preview = preview.slice(0, PREVIEW_LEN) + '...';
    var score = result.risk_score != null ? result.risk_score : result.score;
    var level = (result.risk_level || result.level || 'low').toLowerCase();
    list.unshift({ t: Date.now(), text: preview, score: score, level: level });
    saveLocalHistory(list.slice(0, HISTORY_MAX));
    if (activeHistoryTab === 'local') {
      renderLocalHistory();
    }
  }

  function renderLocalHistory() {
    var list = loadLocalHistory();
    historyList.textContent = '';
    historySection.hidden = list.length === 0 && !backendOnline;
    if (historyHint) {
      historyHint.textContent = 'Saved only in this browser session. Only the first part of each item is kept.';
    }
    clearHistoryBtn.hidden = list.length === 0;

    list.forEach(function (item) {
      var li = el('li');
      li.appendChild(el('span', 'h-text', String(item.text)));
      var when = new Date(item.t);
      var meta = levelWord(String(item.level)) + ', ' + item.score + ' out of 100, ' +
        (isNaN(when.getTime()) ? '' : when.toLocaleString());
      li.appendChild(el('span', 'h-meta', meta));
      historyList.appendChild(li);
    });
  }

  async function loadServerHistoryCount() {
    if (!backendOnline || !serverCount) return;
    try {
      var res = await fetch(API_BASE + '/api/scans?limit=1');
      if (res.ok) {
        var data = await res.json();
        serverCount.textContent = String(data.total || 0);
      }
    } catch (e) {}
  }

  async function renderServerHistory() {
    historyList.textContent = '';
    if (historyHint) {
      historyHint.textContent = 'Persistent audit history from backend SQLite database. Click any scan to load full details.';
    }
    clearHistoryBtn.hidden = true;

    try {
      var res = await fetch(API_BASE + '/api/scans?limit=20');
      if (!res.ok) throw new Error('Failed to load server scans');
      var data = await res.json();
      cachedServerScans = data.scans || [];
      if (serverCount) serverCount.textContent = String(data.total || 0);

      if (cachedServerScans.length === 0) {
        historyList.appendChild(el('li', 'none', 'No scans recorded in server database yet.'));
        return;
      }

      cachedServerScans.forEach(function (scan) {
        var li = el('li');
        var textSpan = el('span', 'h-text', scan.input_preview || scan.scan_id);
        textSpan.style.cursor = 'pointer';
        textSpan.title = 'Click to view full scan result';
        textSpan.addEventListener('click', async function () {
          try {
            var detailRes = await fetch(API_BASE + '/api/scans/' + scan.scan_id);
            if (detailRes.ok) {
              var detail = await detailRes.json();
              renderUnifiedResult(detail, true);
            }
          } catch (e) {
            alert('Could not fetch scan details');
          }
        });
        li.appendChild(textSpan);

        var actions = el('div', 'history-item-actions');
        var metaText = levelWord(scan.risk_level) + ' (' + scan.risk_score + '/100)';
        actions.appendChild(el('span', 'h-meta', metaText));

        // Delete button
        var delBtn = el('button', 'btn-icon', '✕');
        delBtn.title = 'Delete from server database';
        delBtn.addEventListener('click', async function (e) {
          e.stopPropagation();
          if (confirm('Delete scan ' + scan.scan_id + ' from server database?')) {
            try {
              var delRes = await fetch(API_BASE + '/api/scans/' + scan.scan_id, { method: 'DELETE' });
              if (delRes.ok) {
                renderServerHistory();
                loadStats();
              }
            } catch (err) {
              alert('Failed to delete scan: ' + err.message);
            }
          }
        });
        actions.appendChild(delBtn);
        li.appendChild(actions);
        historyList.appendChild(li);
      });
    } catch (err) {
      historyList.appendChild(el('li', 'none', 'Unable to reach backend database.'));
    }
  }

  /* ──────────────────────────────────────────────────────────────────
     Event Handlers
     ────────────────────────────────────────────────────────────────── */
  form.addEventListener('submit', function (event) {
    event.preventDefault();
    performAnalysis(input.value);
  });

  input.addEventListener('keydown', function (event) {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
      event.preventDefault();
      form.requestSubmit();
    }
  });

  document.getElementById('clear').addEventListener('click', function () {
    input.value = '';
    clearError();
    resultBox.hidden = true;
    resultBox.textContent = '';
    input.focus();
  });

  Array.prototype.forEach.call(document.querySelectorAll('[data-example]'), function (btn) {
    btn.addEventListener('click', function () {
      input.value = EXAMPLES[btn.getAttribute('data-example')] || '';
      clearError();
      input.focus();
    });
  });

  clearHistoryBtn.addEventListener('click', function () {
    if (activeHistoryTab === 'local') {
      try { window.localStorage.removeItem(HISTORY_KEY); } catch (e) {}
      renderLocalHistory();
    }
  });

  if (tabLocal) {
    tabLocal.addEventListener('click', function () {
      activeHistoryTab = 'local';
      tabLocal.className = 'tab-btn active';
      tabServer.className = 'tab-btn';
      renderLocalHistory();
    });
  }

  if (tabServer) {
    tabServer.addEventListener('click', function () {
      activeHistoryTab = 'server';
      tabServer.className = 'tab-btn active';
      tabLocal.className = 'tab-btn';
      renderServerHistory();
    });
  }

  /* Initialization */
  renderLocalHistory();
  checkBackendHealth();
}());
