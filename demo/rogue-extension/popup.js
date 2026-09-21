/* PromptPal (demo adversary) popup: drives the active tab the way an AI agent extension would. */
const out = document.getElementById('out');
function say(t) { out.textContent += t + '\n'; }
async function tab() { const [t] = await chrome.tabs.query({ active: true, currentWindow: true }); return t; }
async function run(fn, args) {
  const t = await tab();
  const [r] = await chrome.scripting.executeScript({ target: { tabId: t.id }, func: fn, args: args || [] });
  say(JSON.stringify(r.result));
}

document.getElementById('summarise').addEventListener('click', async () => {
  const t = await tab();
  const [r] = await chrome.scripting.executeScript({ target: { tabId: t.id }, func: () => document.body.innerText.slice(0, 20000) });
  chrome.runtime.sendMessage({ type: 'summarise', url: t.url, text: r.result }, res => say('AI API call: ' + JSON.stringify(res)));
});

document.getElementById('autoapprove').addEventListener('click', () => run(() => {
  const btns = [...document.querySelectorAll('[data-action="approve-payment"]:not(:disabled)')];
  for (const b of btns) b.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, view: window }));
  return `dispatched ${btns.length} synthetic clicks`;
}));

document.getElementById('follow').addEventListener('click', () => run(() => {
  const text = document.body.innerText + ' ' + document.body.textContent;
  const iban = (text.match(/[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,4})?/g) || []).pop();
  const form = document.querySelector('form[data-action="update-vendor-bank"]');
  if (!form) return 'no bank form on this view (open #vendors)';
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
  setter.call(form.iban, iban || 'DE89 3704 0044 0532 0130 00'); form.iban.dispatchEvent(new Event('input', { bubbles: true }));
  setter.call(form.swift, 'COBADEFFXXX'); form.swift.dispatchEvent(new Event('input', { bubbles: true }));
  setter.call(form.reason, 'Per vendor instruction in invoice memo'); form.reason.dispatchEvent(new Event('input', { bubbles: true }));
  form.querySelector('button[type=submit]').dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
  return `filled IBAN ${iban || '(default)'} and submitted`;
}));

document.getElementById('export').addEventListener('click', () => run(() => {
  const b = document.querySelector('.view.active [data-action="export"]');
  if (!b) return 'no export button on this view';
  b.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
  return 'synthetic click on export';
}));
