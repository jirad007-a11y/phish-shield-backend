// server.js - Phish-Shield Express Backend with Full Heuristics
const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json({ limit: '1mb' }));

app.get('/', (req, res) => {
  res.status(200).send('Phish-Shield Backend is live 🚀');
});

// Brand Impersonation & Display Name Heuristics
const KNOWN_BRANDS = ['paramount', 'paramountplus', 'netflix', 'paypal', 'apple', 'amazon', 'microsoft', 'google'];

function analyzeSender(senderName, senderEmail) {
  const flags = [];
  let score = 0;

  if (!senderEmail) return { score, flags };

  const nameLower = (senderName || '').toLowerCase();
  const emailLower = senderEmail.toLowerCase();
  const domain = emailLower.split('@')[1] || '';

  // 1. Display Name / Brand Impersonation Check
  KNOWN_BRANDS.forEach(brand => {
    if (nameLower.includes(brand) || emailLower.includes(brand)) {
      if (!domain.endsWith(`${brand}.com`) && !domain.endsWith(`${brand}plus.com`)) {
        flags.push('SENDER_IMPERSONATION');
        score += 50; // Severe penalty for mimicking Paramount+ on random domains
      }
    }
  });

  // 2. Suspicious TLD / Random String Domain Detection
  if (domain.endsWith('.work') || domain.endsWith('.xyz') || domain.endsWith('.top') || domain.endsWith('.click')) {
    flags.push('SUSPICIOUS_TLD');
    score += 25;
  }

  // 3. Gibberish / High-Entropy Email Usernames (e.g., flxfcqcxipwsyxiy)
  const username = emailLower.split('@')[0] || '';
  if (username.length > 12 && !/[aeiou]/.test(username.slice(0, 8))) {
    flags.push('SUSPICIOUS_SENDER_ADDRESS');
    score += 20;
  }

  return { score, flags };
}

function analyzeText(text) {
  const flags = [];
  let score = 0;
  if (!text) return { score, flags };

  const lower = text.toLowerCase();

  // Social Engineering & Urgency
  if (lower.includes('action needed') || lower.includes('reactivate now') || lower.includes('payment failed') || lower.includes('subscription is currently inactive')) {
    flags.push('SOCIAL_ENGINEERING_PHRASE');
    score += 30;
  }

  if (lower.includes('update your payment') || lower.includes('restore full access')) {
    flags.push('PHISHING_KEYWORDS_FOUND');
    score += 25;
  }

  return { score, flags };
}

app.post('/api/analyze', async (req, res) => {
  try {
    const { urls = [], text = '', senderName = '', senderEmail = '' } = req.body || {};

    console.log('=== [Phish-Shield Backend] Analyzing Request ===');
    console.log('Sender:', senderName, `<${senderEmail}>`);
    console.log('URLs Count:', urls.length);

    // Run Heuristics
    const senderAnalysis = analyzeSender(senderName, senderEmail);
    const textAnalysis = analyzeText(text);

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