const iconCopyUrl = "/static/img/icons.svg#icon-copy";
const iconSuccessUrl = "/static/img/icons.svg#icon-success";

function copyToClipboard(button) {
    const commandElement = button.closest('.copy-container').querySelector('.command-text');
    if (!commandElement) return;

    const text = commandElement.innerText.trim();
    navigator.clipboard.writeText(text)
        .then(() => {
            const iconUse = button.querySelector('svg use');
            if (iconUse) {
                iconUse.setAttribute('href', iconSuccessUrl);
                setTimeout(() => {
                    iconUse.setAttribute('href', iconCopyUrl);
                }, 2000);
            }
        })
        .catch(err => {
            console.error('Error copying text: ', err);
        });
}

document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('.copy-button').forEach(button => {
        button.addEventListener('click', function () {
            copyToClipboard(this);
        });
    });
});
