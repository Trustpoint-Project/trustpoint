document.addEventListener("DOMContentLoaded", function() {
    document.querySelectorAll(".config-button").forEach(function(button) {
        button.addEventListener("click", function() {
            var protocolUrl = this.getAttribute("data-url");
            var modalBody = document.querySelector("#configModal .modal-body");

            fetch(protocolUrl)
                .then(response => response.text()) 
                .then(html => {
                    modalBody.innerHTML = html;

                    var protocolForm = document.querySelector("#protocolConfigForm");
                    if (protocolForm) {
                        protocolForm.addEventListener("submit", function(event) {
                            event.preventDefault();

                            var formData = new FormData(protocolForm);

                            var protocolName = protocolForm.querySelector("input[name='protocol']").value;

                            fetch(protocolUrl, {
                                method: 'POST',
                                body: formData,
                                headers: {
                                    'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]').value
                                }
                            })
                            .then(response => {
                                if (response.ok) {
                                    alert('Form saved successfully!');
                                    var modal = bootstrap.Modal.getInstance(document.querySelector("#configModal"));
                                    modal.hide();
                                } else {
                                    alert('Failed to save the form.');
                                }
                            })
                            .catch(error => {
                                console.error('Error:', error);
                            });
                        });
                    } else {
                        console.error('Form not found in modal');
                    }
                })
                .catch(error => {
                    modalBody.innerHTML = '<p>Error loading form</p>';
                    console.error('Error:', error);
                });
        });
    });
});