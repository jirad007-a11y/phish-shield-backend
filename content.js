// content.js - Resilient Gmail Scraper & Banner Injector
const DEBOUNCE_DELAY_MS = 600;
let debounceTimer = null;
let lastAnalyzedHash = '';
const dismissedEmails = new Set();

console.log('[Phish-Shield] Content script loaded and active on page.');

function getCleanUrl(rawHref) {
  if (!rawHref) return '';
  let clean = rawHref.trim();
  if (clean.includes('google.com/url?') || clean.includes('google.com/url/')) {
    try {
      const parsedUrl = new URL(clean);
      const targetParam = parsedUrl.searchParams.get('q');
      if (targetParam) clean = decodeURIComponent(targetParam);
    } catch (e) {}
  }
  return clean;
}

function translateFlag(flag) {
  if (flag.includes('EXCESSIVE_URL_LENGTH')) return 'Unusually long web address';
  if (flag.includes('PHISHING_KEYWORDS_FOUND')) return 'Contains account login wording';
  if (flag.includes('KNOWN_URL_SHORTENER')) return 'Uses a hidden link shortener';
  if (flag.includes('SENDER_IMPERSONATION') || flag.includes('SENDER_DOMAIN_MISMATCH')) return 'Sender address does not match company identity';
  if (flag.includes('BRAND_SPOOFING')) return 'Mimics a trusted brand name';
  if (flag.includes('SOCIAL_ENGINEERING_PHRASE')) return 'Uses high-pressure or urgent language';
  if (flag.includes('PUNYCODE')) return 'Uses deceptive characters in the web address';
  if (flag.includes('NON_STANDARD_PORT')) return 'Uses an unusual network connection';
  if (flag.includes('HOST_IS_RAW_IP')) return 'Links directly to a raw server IP address';
  if (flag.includes('SUSPICIOUS_THREAD_BAIT')) return 'Fake thread reply with suspicious baiting';
  if (flag.includes('CONVERSATIONAL_SPAM_PATTERNS')) return 'Contains conversational spam baiting';
  if (flag.includes('SENDER_NAME_MISMATCH')) return 'Sender name does not match email handle';
  if (flag.includes('HIGH_ENTROPY_DOMAIN')) return 'Uses a randomly generated domain name';
  return flag.replace(/_/g, ' ').toLowerCase();
}

function extractEmailData() {
  const emailContainers = document.querySelectorAll('.a3s, .ii.gt');
  if (!emailContainers.length) {
    return { urls: [], textBody: '', senderName: '', senderEmail: '', subject: '' };
  }

  const subjectElement = document.querySelector('h2.hP, .hP');
  const subjectText = subjectElement ? subjectElement.innerText.trim() : '';

  let senderName = '';
  let senderEmail = '';
  
  const senderElement = document.querySelector('.gD, span[email], [data-hovercard-id]');
  if (senderElement) {
    senderName = senderElement.getAttribute('name') || senderElement.textContent || '';
    senderEmail = senderElement.getAttribute('email') || senderElement.getAttribute('data-hovercard-id') || '';
    
    if (!senderEmail && senderElement.textContent.includes('@')) {
      const match = senderElement.textContent.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
      if (match) senderEmail = match[0];
    }
  }

  const urlsSet = new Set();
  let fullText = subjectText ? `Subject: ${subjectText}\n` : '';

  emailContainers.forEach(container => {
    fullText += container.innerText + '\n';
    const anchorElements = container.querySelectorAll('a[href]');
    anchorElements.forEach(anchor => {
      const cleanHref = getCleanUrl(anchor.getAttribute('href'));
      if (cleanHref.startsWith('http://') || cleanHref.startsWith('https://')) {
        urlsSet.add(cleanHref);
      }
    });
  });

  return {
    urls: Array.from(urlsSet),
    textBody: fullText.trim(),
    senderName: senderName.trim(),
    senderEmail: senderEmail.trim(),
    subject: subjectText
  };
}

function injectEmailStatusBanner(container, emailSummary, results, senderEmail) {
  const existingBanner = container.querySelector('.phish-shield-banner');
  if (existingBanner) existingBanner.remove();

  if (dismissedEmails.has(senderEmail)) return;

  const score = (emailSummary && typeof emailSummary.riskScore === 'number') ? emailSummary.riskScore : 0;
  console.log('[Phish-Shield GUI Debug] Extracted riskScore for banner:', score, 'from object:', emailSummary);

  const verdict = emailSummary.overallVerdict || 'SAFE';
  const isHighRisk = verdict === 'HIGH_RISK';
  const isSuspicious = verdict === 'SUSPICIOUS';
  const isSafe = verdict === 'SAFE';

  const banner = document.createElement('div');
  banner.className = 'phish-shield-banner';

  const allFlags = [
    ...(emailSummary.senderFlags || []),
    ...(emailSummary.textFlags || []),
    ...(results ? results.flatMap(r => r.flags || []) : [])
  ];
  
  const friendlyReasons = Array.from(new Set(allFlags)).map(translateFlag);

  let icon = '🛡️';
  let title = 'Email Verified Safe';
  let description = 'No phishing indicators or suspicious links detected.';
  
  if (isHighRisk) {
    icon = '🚨';
    title = 'Potential Phishing Attempt Detected';
    description = friendlyReasons.length > 0 ? 'Detected concerns: ' + friendlyReasons.slice(0, 2).join(' • ') : 'High-risk indicators found.';
  } else if (isSuspicious) {
    icon = '⚠️';
    title = 'Exercise Caution With This Email';
    description = friendlyReasons.length > 0 ? 'Detected concerns: ' + friendlyReasons.slice(0, 2).join(' • ') : 'Multiple cautionary indicators found.';
  }

  banner.innerHTML = `
    <div style="display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; width: 100%;">
      <div style="display: flex; align-items: flex-start; gap: 12px;">
        <span style="font-size: 20px;">${icon}</span>
        <div>
          <strong>${title}</strong>
          <p style="margin: 4px 0 ${isSafe ? '0' : '4px'} 0; font-size: 12px;">
            ${description}
          </p>
          ${!isSafe ? `
            <button class="phish-shield-dismiss-btn" style="background: none; border: none; padding: 0; color: inherit; text-decoration: underline; cursor: pointer; font-size: 11px; font-weight: bold; opacity: 0.8;">
              Trust sender / Dismiss warning
            </button>
          ` : ''}
        </div>
      </div>
      <div style="background: rgba(0,0,0,0.06); padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; white-space: nowrap;">
        Risk Score: ${score}/100
      </div>
    </div>
  `;

  let bgCol = '#e6f4ea';
  let borderCol = '#34a853';
  let textCol = '#137333';

  if (isHighRisk) {
    bgCol = '#fce8e6';
    borderCol = '#d93025';
    textCol = '#c5221f';
  } else if (isSuspicious) {
    bgCol = '#fef7e0';
    borderCol = '#f9ab00';
    textCol = '#b06000';
  }

  Object.assign(banner.style, {
    backgroundColor: bgCol,
    border: `1px solid ${borderCol}`,
    color: textCol,
    padding: '12px 16px',
    borderRadius: '6px',
    marginBottom: '16px',
    fontFamily: 'Arial, sans-serif',
    fontSize: '13px',
    boxShadow: '0 1px 3px rgba(0,0,0,0.1)'
  });

  if (!isSafe) {
    const dismissBtn = banner.querySelector('.phish-shield-dismiss-btn');
    if (dismissBtn) {
      dismissBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        dismissedEmails.add(senderEmail);
        document.querySelectorAll('.phish-shield-banner').forEach(b => b.remove());
      });
    }
  }

  container.insertBefore(banner, container.firstChild);
}

function processEmailBody() {
  try {
    const { urls, textBody, senderName, senderEmail, subject } = extractEmailData();
    if (urls.length === 0 && !textBody && !senderEmail) return;
    if (dismissedEmails.has(senderEmail)) return;

    const currentHash = `${senderEmail}|${[...urls].sort().join('|')}|${textBody.length}`;
    if (currentHash === lastAnalyzedHash) return;

    chrome.runtime.sendMessage(
      { action: 'ANALYZE_URLS', urls, text: textBody, senderName, senderEmail, subject },
      (response) => {
        if (chrome.runtime.lastError) return;

        if (response && response.success) {
          lastAnalyzedHash = currentHash;
          const responseData = response.data || {};
          const emailSummary = responseData.emailSummary || { overallVerdict: 'SAFE', riskScore: 0 };
          const results = responseData.results || [];
          
          const emailContainers = document.querySelectorAll('.a3s');
          emailContainers.forEach(container => {
            injectEmailStatusBanner(container, emailSummary, results, senderEmail);
          });
        }
      }
    );
  } catch (err) {
    console.error('[Phish-Shield] Error in scanner process:', err);
  }
}

function initializeObserver() {
  const observer = new MutationObserver(() => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(processEmailBody, DEBOUNCE_DELAY_MS);
  });

  const targetNode = document.querySelector('div[role="main"]') || document.body;
  observer.observe(targetNode, { childList: true, subtree: true });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeObserver);
} else {
  initializeObserver();
}