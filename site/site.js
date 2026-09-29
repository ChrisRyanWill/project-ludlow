// Loads the interactive demo only when someone asks for it (it pulls in ~400 KB of cryptography).
const start = document.getElementById('try-load');
start?.addEventListener('click', async () => {
  start.disabled = true;
  start.textContent = 'Loading the cryptography...';
  try {
    const demo = await import('./try.js');
    start.parentElement.replaceChildren();
    await demo.mount(document.getElementById('try-root'));
  } catch {
    start.disabled = false;
    start.textContent = 'Could not load it. Try again';
  }
});
