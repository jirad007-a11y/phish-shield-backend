// server.js - Phish-Shield Express Backend with Full Heuristics & Rate Limiting
const express = require('express');
const cors = require('cors');
const { rateLimit } = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3001;

// Trust proxy (required for correct client IP detection behind Render, Heroku, or load balancers)
app.set('trust proxy', 1);

app.use(cors());
app.use(express.json({ limit: '1mb' }));

// 1. Global Baseline Rate Limiter (Prevents general traffic flooding)
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15-minute window
  limit: 100, // Limit each IP to 100 requests per window
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many requests from this IP, please try again later.'
  }
});

app.use(globalLimiter);

// 2. Strict Rate Limiter for Analysis Endpoint (Protects expensive heuristics/scans)
const analyzeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15-minute window
  limit: 30, // Limit each IP to 30 analysis requests per window
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Scan limit reached. Please wait a few minutes before analyzing more emails.'
  }
});

app.get('/', (req, res) => {
  res.status(200).send('Phish-Shield Backend is live 🚀');
});

// Brand Impersonation & Display Name Heuristics
const KNOWN_BRANDS = [
  'paramount', 'paramountplus', 'netflix', 'paypal', 
  'apple', 'amazon', 'microsoft', 'google', 'fidelity', 'fidelitylife'
];

function analyzeSender(senderName = '', senderEmail = '', subject = '') {
  const flags = [];
  let score = 0;

  if (!senderEmail) return { score, flags };

  const rawName = (senderName || '').toLowerCase();
  const emailLower = senderEmail.toLowerCase();
  const parts = emailLower.split('@');
  const username = parts[0] || '';
  const domain = parts[1] || '';
  const domainBody = domain.split('.')[0] || '';

  // 1. Normalize Display Name: Remove spaces, periods, underscores, and dashes
  // Catches obfuscated trickery like "FID.ELI.TY__L.I.FE" -> "fidelitylife"
  const normalizedName = rawName.replace(/[^a-z0-9]/g, '');

  // 2. Display Name / Brand Impersonation Check
  KNOWN_BRANDS.forEach(brand => {
    if (normalizedName.includes(brand) || emailLower.includes(brand)) {
      if (
        !domain.endsWith(`${brand}.com`) && 
        !domain.endsWith(`${brand}plus.com`) && 
        !domain.endsWith(`${brand}life.com`)
      ) {
        flags.push('SENDER_IMPERSONATION');
        score += 50; // Severe penalty for mimicking brands on random domains
      }
    }
  });

  // 3. High-Entropy / Random Gibberish Domain Detection (e.g. rvcmefnnoukmfjeyptqxyiof)
  const domainVowelCount = (domainBody.match(/[aeiou]/g) || []).length;
  if (domainBody.length > 15 && (domainVowelCount / domainBody.length) < 0.25) {
    flags.push('HIGH_ENTROPY_DOMAIN');
    score += 40;
  }

  // 4. Obfuscation & Character Manipulation Check in Display Name
  if (/[a-z]\.[a-z]\.[a-z]/i.test(rawName) || /_[a-z]_[a-z]/i.test(rawName)) {
    flags.push('NAME_OBFUSCATION_ATTEMPT');
    score += 25;
  }

  // 5. IP Address Detection in Subject or Sender Address
  if (
    /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(subject) || 
    /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(senderEmail)
  ) {
    flags.push('IP_ADDRESS_IN_HEADER');
    score += 20;
  }

  // 6. Excessive Repeating Subdomains or Suspicious Structural Patterns
  if ((domain.match(/\./g) || []).length > 3 || /ltd|survey|click|track|support/i.test(username)) {
    flags.push('SUSPICIOUS_SENDER_STRUCTURE');
    score += 20;
  }

  // 7. Suspicious TLD / Random Domain Extension Detection
  if (
    domain.endsWith('.work') || 
    domain.endsWith('.xyz') || 
    domain.endsWith('.top') || 
    domain.endsWith('.click') || 
    domain.endsWith('.gmx.net')
  ) {
    flags.push('SUSPICIOUS_TLD');
    score += 25;
  }

  // 8. Gibberish / High-Entropy Email Usernames
  if (username.length > 12 && !/[aeiou]/.test(username.slice(0, 8))) {
    flags.push('SUSPICIOUS_SENDER_ADDRESS');
    score += 20;
  }

  return { score, flags };
}

function analyzeText(text = '', subject = '') {
  const flags = [];
  let score = 0;
  const combinedText = `${subject} ${text}`.toLowerCase();

  if (!combinedText.trim()) return { score, flags };

  // 1. Social Engineering & Urgency
  if (
    combinedText.includes('action needed') || 
    combinedText.includes('reactivate now') || 
    combinedText.includes('payment failed') || 
    combinedText.includes('subscription is currently inactive')
  ) {
    flags.push('SOCIAL_ENGINEERING_PHRASE');
    score += 30;
  }

  if (combinedText.includes('update your payment') || combinedText.includes('restore full access')) {
    flags.push('PHISHING_KEYWORDS_FOUND');
    score += 25;
  }

  // 2. Spam / Adult / Clickbait Patterns
  if (
    combinedText.includes('(nsfw)') || 
    combinedText.includes('trick for free') || 
    combinedText.includes('big pharma') || 
    combinedText.includes('impotence') ||
    combinedText.includes('changing male sexual health')
  ) {
    flags.push('SPAM_CLICKBAIT_PATTERNS');
    score += 35;
  }

  return { score, flags };
}

// Apply the strict analyzeLimiter middleware directly to the POST route
app.post('/api/analyze', analyzeLimiter, async (req, res) => {
  try {
    const { urls = [], text = '', senderName = '', senderEmail = '', subject = '' } = req.body || {};

    console.log('=== [Phish-Shield Backend] Analyzing Request ===');
    console.log('Sender:', senderName, `<${senderEmail}>`);
    console.log('Subject:', subject);
    console.log('URLs Count:', urls.length);

    // Run Heuristics
    const senderAnalysis = analyzeSender(senderName, senderEmail, subject);
    const textAnalysis = analyzeText(text, subject);

    const senderFlags = senderAnalysis.flags;
    const textFlags = textAnalysis.flags;
    
    let totalScore = senderAnalysis.score + textAnalysis.score;

    // Additional URL scoring
    if (urls.length > 0) {
      totalScore += 10;
    }

    const finalScore = Math.min(totalScore, 100);
    let overallVerdict = 'SAFE';

    if (finalScore >= 60) {
      overallVerdict = 'HIGH_RISK';
    } else if (finalScore >= 30) {
      overallVerdict = 'SUSPICIOUS';
    }

    console.log(`[Result] Verdict: ${overallVerdict} | Score: ${finalScore}/100`);

    res.json({
      success: true,
      emailSummary: {
        overallVerdict,
        riskScore: finalScore,
        senderFlags,
        textFlags
      },
      results: urls.map(url => ({ url, flags: [], score: 0 }))
    });

  } catch (err) {
    console.error('Error in /api/analyze:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));