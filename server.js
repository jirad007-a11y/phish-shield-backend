// server.js - Express backend with Punycode, URL Shortener Resolution, and Display Name Spoofing Detection
const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3001; // Allows Render to assign its own port

app.use(cors());
app.use(express.json());

// Simple Levenshtein distance calculator for brand spoofing detection
function getLevenshteinDistance(a, b) {
  const matrix = [];
  for (let i = 0; i <= b.length; i++) { matrix[i] = [i]; }
  for (let j = 0; j <= a.length; j++) { matrix[0][j] = j; }
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          Math.min(matrix[i][j - 1] + 1, // insertion
          matrix[i - 1][j] + 1) // deletion
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

const TRUSTED_BRANDS = ['paypal', 'google', 'microsoft', 'apple', 'amazon', 'netflix', 'chase', 'bankofamerica'];
const KNOWN_SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'buff.ly', 'is.gd', 'ift.tt'];

// Helper to resolve short URLs via a quick HEAD request
async function resolveShortUrl(url) {
  try {
    const parsed = new URL(url);
    if (KNOWN_SHORTENERS.some(shortener => parsed.hostname.includes(shortener))) {
      // Use native fetch to follow redirect chain (requires Node 18+)
      const response = await fetch(url, { method: 'HEAD', redirect: 'follow' });
      return response.url || url;
    }
  } catch (e) {
    // If resolution fails or times out, return original
  }
  return url;
}

// Detector for Display Name Impersonation
function checkDisplayNameSpoofing(senderName = '', senderEmail = '') {
  let flags = [];
  let penalty = 0;

  const lowerName = senderName.toLowerCase();
  const lowerEmail = senderEmail.toLowerCase();

  // Internal team names or typical high-risk identities
  const internalNames = ['jared mullins', 'it support', 'helpdesk', 'admin', 'hr'];
  
  const claimsToBeInternal = internalNames.some(name => lowerName.includes(name));
  const isActualInternal = lowerEmail.endsWith('@teds.com');

  if (claimsToBeInternal && !isActualInternal) {
    flags.push('SENDER_IMPERSONATION');
    penalty += 45; // Heavy penalty for pretending to be an internal entity from an external email
  }

  return { flags, penalty };
}

async function analyzeEmail(urls = [], text = '', senderName = '', senderEmail = '') {
  let riskScore = 0;
  let senderFlags = [];
  let textFlags = [];
  let results = [];

  const lowerText = text ? text.toLowerCase() : '';
  const lowerSender = senderEmail ? senderEmail.toLowerCase() : '';

  // 1. Sender Domain Check
  if (lowerSender && !lowerSender.endsWith('@teds.com')) {
    senderFlags.push('SENDER_DOMAIN_MISMATCH');
    riskScore += 20;
  }

  // 2. Display Name Spoofing Check
  const spoofCheck = checkDisplayNameSpoofing(senderName, senderEmail);
  if (spoofCheck.flags.length > 0) {
    senderFlags.push(...spoofCheck.flags);
    riskScore += spoofCheck.penalty;
  }

  // 3. Social Engineering Keywords
  const urgentKeywords = ['urgent', 'immediate action', 'suspended', 'verify', 'click here', 'account alert', 'inactive'];
  let keywordHits = urgentKeywords.filter(keyword => lowerText.includes(keyword));
  if (keywordHits.length > 0) {
    textFlags.push('SOCIAL_ENGINEERING_PHRASE');
    riskScore += keywordHits.length * 15;
  }

  // 4. Independent Link Analysis with Shortener Resolution & Punycode Checks
  if (Array.isArray(urls) && urls.length > 0) {
    for (let rawUrl of urls) {
      let urlFlags = [];
      
      // Resolve short URLs to their final hidden destination
      let finalUrl = await resolveShortUrl(rawUrl);
      if (finalUrl !== rawUrl) {
        urlFlags.push('KNOWN_URL_SHORTENER');
        riskScore += 30;
      }

      const lowerUrl = finalUrl.toLowerCase();

      // Check for Punycode / Homoglyph deceptive characters (xn--)
      try {
        const hostname = new URL(finalUrl).hostname.toLowerCase();
        if (hostname.includes('xn--')) {
          urlFlags.push('PUNYCODE');
          riskScore += 40; // Heavy penalty for deceptive Internationalized Domain Names
        }

        // Check Brand Impersonation via Levenshtein distance
        TRUSTED_BRANDS.forEach(brand => {
          if (!hostname.includes(`${brand}.com`) && !hostname.endsWith(`.${brand}.com`)) {
            const domainParts = hostname.split('.');
            domainParts.forEach(part => {
              const distance = getLevenshteinDistance(part, brand);
              if (distance > 0 && distance <= 2 && part.length >= brand.length - 1) {
                urlFlags.push('BRAND_SPOOFING');
                riskScore += 50; 
              }
            });
          }
        });
      } catch (e) {
        TRUSTED_BRANDS.forEach(brand => {
          if (lowerUrl.includes(brand) && !lowerUrl.includes(`${brand}.com`)) {
            urlFlags.push('BRAND_SPOOFING');
            riskScore += 50;
          }
        });
      }

      results.push({ url: finalUrl, flags: Array.from(new Set(urlFlags)) });
    }
  }

  // Cap score between 0 and 100
  riskScore = Math.min(Math.max(parseInt(riskScore) || 0, 0), 100);

  // Verdict logic
  let overallVerdict = 'SAFE';
  if (riskScore >= 60) {
    overallVerdict = 'HIGH_RISK';
  } else if (riskScore >= 25) {
    overallVerdict = 'SUSPICIOUS';
  }

  return {
    emailSummary: {
      overallVerdict,
      riskScore,
      senderFlags,
      textFlags
    },
    results
  };
}

app.post('/api/analyze', async (req, res) => {
  try {
    const { urls, text, senderName, senderEmail } = req.body;
    
    console.log(`\n[${new Date().toISOString()}] Analyzing request from: ${senderEmail} (${senderName})`);
    const analysis = await analyzeEmail(urls, text, senderName, senderEmail);
    console.log(` -> Risk Score: ${analysis.emailSummary.riskScore} | Verdict: ${analysis.emailSummary.overallVerdict}`);

    res.json({
      success: true,
      data: analysis
    });
  } catch (err) {
    console.error('[Server] Error processing analysis request:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`[Phish-Shield] Backend analysis server running on http://localhost:${PORT}`);
});