document.addEventListener('DOMContentLoaded', function() {
    // Get the device ID from the global variable defined in the template.
    const deviceId = window.deviceId;
    if (!deviceId) {
        console.error('Device ID is not defined.');
        return;
    }

    // Get the target redirect URL from the global variable.
    const redirectURL = window.onboardRedirectURL;
    if (!redirectURL) {
        console.error('Redirect URL is not defined.');
        return;
    }

    // Get the status element from the DOM.
    const statusElement = document.getElementById('onboard-status');
    if (!statusElement) {
        console.error('Status element not found.');
        return;
    }

    const checkOnboardStatus = function() {
        fetch(`/devices/onboard-status/?device_id=${deviceId}`, {
            credentials: 'include'
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                console.error('Error:', data.error);
                statusElement.textContent = 'Error fetching status.';
                statusElement.classList.remove('alert-info', 'alert-success');
                statusElement.classList.add('alert-danger');
            } else {
                if (data.onboarded) {
                    console.log('Device is onboarded.');
                    statusElement.textContent = 'Device is onboarded.';
                    statusElement.classList.remove('alert-info');
                    statusElement.classList.add('alert-success');
                    clearInterval(intervalId);
                    window.location.href = redirectURL;
                } else {
                    console.log('Device is not onboarded.');
                    statusElement.textContent = 'Device is not onboarded yet.';
                    statusElement.classList.remove('alert-success', 'alert-danger');
                    statusElement.classList.add('alert-info');
                }
            }
        })
        .catch(error => {
            console.error('Error fetching onboard status:', error);
            statusElement.textContent = 'Error fetching status.';
            statusElement.classList.remove('alert-info', 'alert-success');
            statusElement.classList.add('alert-danger');
        });
    };

    const intervalId = setInterval(checkOnboardStatus, 2000);
});
