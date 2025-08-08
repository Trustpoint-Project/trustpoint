document.addEventListener('DOMContentLoaded', function () {
    const configFields = document.getElementById('hsm-config-fields');
    const messageContainer = document.getElementById('hsm-message-container');
    const submitBtn = document.querySelector('button[form="hsm_configuration"]');
    const form = document.getElementById('hsm_configuration');

    const tokenLabelField = document.querySelector('input[name="label"]');
    const slotNumberField = document.querySelector('input[name="slot"]');
    const modulePathField = document.querySelector('input[name="module_path"]');

    // Get all hsm_type radio buttons or select options
    const hsmTypeInputs = document.querySelectorAll('input[name="hsm_type"], select[name="hsm_type"]');

    function getSelectedHSMType() {
        const checkedRadio = document.querySelector('input[name="hsm_type"]:checked');
        const selectedOption = document.querySelector('select[name="hsm_type"]');

        if (checkedRadio) return checkedRadio.value;
        if (selectedOption) return selectedOption.value;
        return null;
    }

    function toggleFields() {
        const selectedValue = getSelectedHSMType();
        const isSoftHSM = selectedValue === 'softhsm';
        const isPhysicalHSM = selectedValue === 'physical';

        // Clear existing message
        if (messageContainer) {
            messageContainer.innerHTML = '';
        }

        if (isPhysicalHSM) {
            // Hide configuration fields for Physical HSM
            if (configFields) {
                configFields.style.display = 'none';
            }

            // Show "not supported" message
            if (messageContainer) {
                messageContainer.innerHTML = `
                    <div class="alert alert-warning mt-3">
                        <strong>Physical HSM Support</strong><br>
                        Physical HSM configuration is not yet supported. This feature will be available in a future release.
                    </div>
                `;
            }

            // Disable submit button
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.textContent = 'Not Available';
                submitBtn.classList.add('btn-secondary');
                submitBtn.classList.remove('btn-primary');
            }

        } else if (isSoftHSM) {
            // Show configuration fields for SoftHSM
            if (configFields) {
                configFields.style.display = 'block';
            }

            // Configure fields for SoftHSM
            if (tokenLabelField) {
                tokenLabelField.value = 'TrustPoint-SoftHSM';
                tokenLabelField.disabled = true;
                tokenLabelField.style.opacity = '0.6';
                tokenLabelField.removeAttribute('required');
            }

            if (slotNumberField) {
                slotNumberField.value = '0';
                slotNumberField.disabled = true;
                slotNumberField.style.opacity = '0.6';
                slotNumberField.removeAttribute('required');
            }

            if (modulePathField) {
                modulePathField.value = '/usr/lib/softhsm/libsofthsm2.so';
                modulePathField.disabled = true;
                modulePathField.style.opacity = '0.6';
                modulePathField.removeAttribute('required');
            }

            // Show info message for SoftHSM
            if (messageContainer) {
                messageContainer.innerHTML = `
                    <div class="alert alert-info mt-3">
                        <strong>SoftHSM Configuration</strong><br>
                        SoftHSM settings are automatically configured with default values.
                    </div>
                `;
            }

            // Enable submit button
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Configure HSM';
                submitBtn.classList.add('btn-primary');
                submitBtn.classList.remove('btn-secondary');
            }

        } else {
            // No selection - show all fields as enabled
            if (configFields) {
                configFields.style.display = 'block';
            }

            const allFields = [tokenLabelField, slotNumberField, modulePathField];
            allFields.forEach(field => {
                if (field) {
                    field.disabled = false;
                    field.style.opacity = '1';
                    field.setAttribute('required', 'required');
                }
            });

            // Enable submit button
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Configure HSM';
                submitBtn.classList.add('btn-primary');
                submitBtn.classList.remove('btn-secondary');
            }
        }
    }

    // Initial toggle on page load
    toggleFields();

    // Add event listeners for changes
    hsmTypeInputs.forEach(input => {
        input.addEventListener('change', toggleFields);
    });

    // Handle form submission for SoftHSM - enable fields temporarily
    if (form) {
        form.addEventListener('submit', function (e) {
            const selectedValue = getSelectedHSMType();
            if (selectedValue === 'softhsm') {
                // Temporarily enable fields for form submission
                if (tokenLabelField) tokenLabelField.disabled = false;
                if (slotNumberField) slotNumberField.disabled = false;
                if (modulePathField) modulePathField.disabled = false;
            } else if (selectedValue === 'physical') {
                // Prevent form submission for physical HSM
                e.preventDefault();
                return false;
            }
        });
    }
});