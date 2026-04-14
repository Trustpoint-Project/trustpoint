document.addEventListener('DOMContentLoaded', function() {
    const buildBtn = document.getElementById('build-docs-btn');
    const rebuildBtn = document.getElementById('rebuild-docs-btn');
    const loadingArea = document.getElementById('docs-loading');
    const statusArea = document.getElementById('docs-status-area');

    function triggerBuild(url, token) {

        if (loadingArea.classList.contains('d-none') === false) return;


        if (statusArea) statusArea.classList.add('d-none');
        if (loadingArea) loadingArea.classList.remove('d-none');


        fetch(url, {
            method: 'POST',
            headers: { 'X-CSRFToken': token, 'Content-Type': 'application/json' }
        })
        .then(response => {
            if (response.ok) {

                window.location.href = window.location.href;
            } else {
                throw new Error('Server returned an error');
            }
        })
        .catch(error => {
            console.error('Build error:', error);
            alert('Documentation build failed. Check terminal logs.');

            if (statusArea) statusArea.classList.remove('d-none');
            if (loadingArea) loadingArea.classList.add('d-none');
        });
    }


    if (buildBtn) {
        buildBtn.addEventListener('click', function(e) {
            e.preventDefault();
            triggerBuild(buildBtn.getAttribute('data-url'), buildBtn.getAttribute('data-csrf'));
        });
    }


    if (rebuildBtn) {
        rebuildBtn.addEventListener('click', function(e) {
            e.preventDefault();
            triggerBuild(rebuildBtn.getAttribute('data-url'), rebuildBtn.getAttribute('data-csrf'));
        });
    }
});