// background.js - Rover Watch Background Service Worker

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'ANALYZE_URLS') {
    
    // Live Cloud Backend API Endpoint
    fetch('https://phish-shield-backend.onrender.com/api/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        urls: request.urls,
        text: request.text,
        senderName: request.senderName,
        senderEmail: request.senderEmail,
        subject: request.subject
      })
    })
    .then(response => {
      if (!response.ok) {
        throw new Error(`Server returned HTTP status ${response.status}`);
      }
      return response.json();
    })
    .then(data => {
      sendResponse({ success: true, data: data });
    })
    .catch(error => {
      console.error('[Rover Watch Background] Error calling cloud backend:', error);
      sendResponse({ success: false, error: error.message });
    });

    // Required for asynchronous sendResponse in Chrome MV3
    return true; 
  }
});