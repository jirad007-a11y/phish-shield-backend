// server.js - Phish-Shield Express Backend
const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json({ limit: '1mb' }));

// Health check endpoint for Render
app.get('/', (req, res) => {
  res.status(200).send('Phish-Shield Backend is live and running 🚀');
});

// Main analysis endpoint
app.post('/api/analyze', async (req, res) => {
  try {
    const { urls = [], text = '', senderName = '', senderEmail = '' } = req.body || {};

    console.log('=== [Phish-Shield Backend Debug] ===');
    console.log('Sender Email Received:', senderEmail || '(Empty)');
    console.log('Sender Name Received:', senderName || '(Empty)');
    console.log('URLs Count Received:', urls.length);
    console.log('URLs List:', urls);
    console.log('Text Length Received:', text.length);

    // TODO: Replace or connect this with your actual heuristics / analysis engine
    // For now, returning a sample structured response to test the round-trip connection.
    // If you already have analysis functions, call them here:
    // const analysisResult = runPhishingAnalysis({ urls, text, senderName, senderEmail });

    // Mock evaluation for demonstration if heuristics aren't wired up yet:
    let riskScore = 0;
    let overallVerdict = 'SAFE';
    const senderFlags = [];
    const textFlags = [];

    // Simple heuristic example check (customize based on your existing code)
    if (senderEmail && (senderEmail.includes('support') || senderEmail.includes('verify')) && !senderEmail.endsWith('trusted-domain.com')) {
      senderFlags.push('SENDER_DOMAIN_MISMATCH');
      riskScore += 40;
    }

    if (text.toLowerCase().includes('password') || text.toLowerCase().includes('verify account') || text.toLowerCase().includes('urgent')) {
      textFlags.push('PHISHING_KEYWORDS_FOUND');
      riskScore += 35;
    }

    if (urls.length > 0) {
      riskScore += (urls.length * 5);
    }

    if (riskScore >= 70) {
      overallVerdict = 'HIGH_RISK';
    } else if (riskScore >= 30) {
      overallVerdict = 'SUSPICIOUS';
    }

    const emailSummary = {
      overallVerdict,
      riskScore: Math.min(riskScore, 100),
      senderFlags,
      textFlags
    };

    const results = urls.map(url => ({
      url,
      flags: [],
      score: 0
    }));

    console.log('Sending response -> Verdict:', overallVerdict, '| Score:', emailSummary.riskScore);

    res.json({
      success: true,
      emailSummary,
      results
    });

  } catch (err) {
    console.error('Error in /api/analyze:', err);
    res.status(500).json({ success: false, error: 'Internal server error during analysis' });
  }
});

app.listen(PORT, () => {
  console.log(`Phish-Shield server listening on port ${PORT}`);
});