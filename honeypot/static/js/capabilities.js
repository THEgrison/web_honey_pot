async function postBeacon() {
  const payload = {
    js: true,
    href: window.location.href,
    ts: new Date().toISOString(),
    cookiesEnabled: navigator.cookieEnabled,
  };

  try {
    await fetch('/cap/js-beacon', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      keepalive: true,
    });
    const status = document.getElementById('js-status');
    if (status) {
      status.textContent = 'JavaScript: execute';
    }
  } catch (_e) {
    const status = document.getElementById('js-status');
    if (status) {
      status.textContent = 'JavaScript: erreur beacon';
    }
  }
}

document.addEventListener('DOMContentLoaded', () => {
  postBeacon();
});
