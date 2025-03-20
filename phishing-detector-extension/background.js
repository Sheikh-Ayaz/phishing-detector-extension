chrome.webNavigation.onCompleted.addListener((details) => {
  chrome.tabs.get(details.tabId, (tab) => {
    fetch('http://localhost:5000/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: tab.url })
    })
    .then(response => {
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      return response.json();
    })
    .then(data => {
      if (data.phishing) {
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icon.png',
          title: 'Phishing Alert!',
          message: 'This site is suspicious.'
        });
      }
    })
    .catch(error => console.error('Error:', error));
  });
});