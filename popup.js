document.getElementById('scanBtn').addEventListener('click', async () => {
  const resultsDiv = document.getElementById('results');
  resultsDiv.textContent = 'Scanning active page...';

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  chrome.tabs.sendMessage(tab.id, { action: 'MANUAL_SCAN' }, (response) => {
    if (chrome.runtime.lastError) {
      resultsDiv.textContent = 'Refresh page or navigate to a webmail tab.';
      return;
    }
    resultsDiv.textContent = `Found ${response?.linksCount || 0} links to evaluate.`;
  });
});