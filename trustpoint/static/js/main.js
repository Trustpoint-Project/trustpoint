function updateOnlineStatus() {
  const banner = document.getElementById('offline-banner');
  if (!navigator.onLine) {
    banner.style.display = 'block';

    // Désactiver tous les boutons (optionnel)
    document.querySelectorAll('button, a.btn').forEach(el => {
      el.setAttribute('disabled', true);
      el.classList.add('disabled');
    });
  } else {
    banner.style.display = 'none';

    // Réactiver les boutons
    document.querySelectorAll('button, a.btn').forEach(el => {
      el.removeAttribute('disabled');
      el.classList.remove('disabled');
    });
  }
}

// Initial check
window.addEventListener('load', updateOnlineStatus);
window.addEventListener('online', updateOnlineStatus);
window.addEventListener('offline', updateOnlineStatus);
