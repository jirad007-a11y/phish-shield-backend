const axios = require('axios');

const API_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY;
const SAFE_BROWSING_URL = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`;

/**
 * Checks an array of URLs against the Google Safe Browsing API v4.
 * @param {string[]} urls - List of URLs to analyze.
 * @returns {Promise<Object>} Map of URLs to Google threat match objects.
 */
async function checkUrlsWithSafeBrowsing(urls) {
  if (!urls || !Array.isArray(urls) || urls.length === 0) {
    return {};
  }

  // Filter out invalid or non-HTTP(S) URLs before sending to Google
  const validUrls = urls.filter(u => typeof u === 'string' && (u.startsWith('http://') || u.startsWith('https://')));

  if (validUrls.length === 0) {
    return {};
  }

  // Google API allows up to 500 threat entries per request payload
  const requestBody = {
    client: {
      clientId: "anti-phishing-shield-backend",
      clientVersion: "1.0.0"
    },
    threatInfo: {
      threatTypes: [
        "MALWARE",
        "SOCIAL_ENGINEERING", // Phishing & deceptive sites
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION"
      ],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: validUrls.map(url => ({ url }))
    }
  };

  try {
    const response = await axios.post(SAFE_BROWSING_URL, requestBody, { timeout: 5000 });
    const matches = response.data?.matches || [];

    // Map responses back to each URL key
    const results = {};
    validUrls.forEach(url => {
      const match = matches.find(m => m.threat.url === url);
      if (match) {
        const formattedType = match.threatType.replace(/_/g, ' ');
        results[url] = {
          isFlagged: true,
          threatType: match.threatType,
          summary: `Flagged by Google Safe Browsing as ${formattedType}.`
        };
      } else {
        results[url] = {
          isFlagged: false,
          threatType: null,
          summary: "No threats detected by Google Safe Browsing."
        };
      }
    });

    return results;
  } catch (error) {
    console.error("Google Safe Browsing API Error:", error.response?.data || error.message);
    // Graceful fallback if API key is missing, quota is reached, or service times out
    return {};
  }
}

module.exports = { checkUrlsWithSafeBrowsing };