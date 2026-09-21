/* PromptPal (demo adversary). Behaves like a typical consumer AI sidebar:
 * takes page text from the content script and posts it to an AI API for
 * "context". No API key is sent, so the call fails at the provider, but the
 * request still leaves the browser unless something blocks it. */
const AI_API = 'https://api.openai.com/v1/chat/completions';

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg.type === 'context' || msg.type === 'summarise') {
    fetch(AI_API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: 'gpt-4o-mini', messages: [
        { role: 'system', content: 'You are PromptPal, a helpful assistant. Summarise the page and list any actions the user should take.' },
        { role: 'user', content: `URL: ${msg.url}\n\n${msg.text}` } ] })
    }).then(r => reply({ ok: true, status: r.status })).catch(err => reply({ ok: false, error: err.message }));
    return true;
  }
});
