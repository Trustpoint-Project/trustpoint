const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]')
const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl))

// ---------------------------------------- Add certificate Authorities ----------------------------------------

const localIssuingCaOptions = document.getElementById('tp-form-local-issuing-ca');
const localIssuingCaRadio = document.getElementById('local-issuing-ca-radio');
const localIssuingCaImportFilesRadio = document.getElementById('local-issuing-ca-import-files');
const localIssuingCaRequestRadio = document.getElementById('local-issuing-ca-request');
if (localIssuingCaOptions) {
    localIssuingCaRadio.addEventListener('change', certAuthRadioFormChange);
}

const remoteIssuingCaOptions = document.getElementById('tp-form-remote-issuing-ca');
const remoteIssuingCaRadio = document.getElementById('remote-issuing-ca-radio');
const remoteIssuingCaEstRadio = document.getElementById('remote-issuing-ca-est');
const remoteIssuingCaCmpRadio = document.getElementById('remote-issuing-ca-cmp');
if (remoteIssuingCaRadio) {
    remoteIssuingCaRadio.addEventListener('change', certAuthRadioFormChange);
}

function certAuthRadioFormChange() {
    if (localIssuingCaRadio.checked) {
        localIssuingCaOptions.hidden = false;
        remoteIssuingCaOptions.hidden = true;

        localIssuingCaImportFilesRadio.checked = true;
        localIssuingCaRequestRadio.checked = false;

    } else if (remoteIssuingCaRadio.checked) {
        localIssuingCaOptions.hidden = true;
        remoteIssuingCaOptions.hidden = false;

        remoteIssuingCaEstRadio.checked = true;
        remoteIssuingCaCmpRadio.checked = false;
    }
}

const modal = document.getElementById('addCaModal');
if (modal) {
    modal.addEventListener('hidden.bs.modal', resetIssuingCaRadios);
}

function resetIssuingCaRadios() {

    localIssuingCaOptions.hidden = true;
    localIssuingCaRadio.checked = false;
    localIssuingCaImportFilesRadio.checked = true;
    localIssuingCaRequestRadio.checked = false;

    remoteIssuingCaOptions.hidden = false;
    remoteIssuingCaRadio.checked = true;
    remoteIssuingCaEstRadio.checked = true;
    remoteIssuingCaCmpRadio.checked = false;
}

const p12FileForm = document.getElementById('p12-file-form');
const p12FileRadio = document.getElementById('p12-file-radio');
if (p12FileRadio) {
    p12FileRadio.addEventListener('change', chooseFileFormatForm);
}

const pemFileForm = document.getElementById('pem-file-form');
const pemFileRadio = document.getElementById('pem-file-radio');
if (pemFileRadio) {
    pemFileRadio.addEventListener('change', chooseFileFormatForm);
}

function chooseFileFormatForm() {
    if (p12FileRadio.checked) {
        p12FileForm.hidden = false;
        pemFileForm.hidden = true;
    } else if (pemFileRadio.checked) {
        p12FileForm.hidden = true;
        pemFileForm.hidden = false;
    }
}
// ---------------------------------------- Table Checkbox Column ----------------------------------------

const checkboxColumn = document.querySelector('#checkbox-column > input');
const checkboxes = document.querySelectorAll('.row_checkbox > input');
const tableSelectButtons = document.querySelectorAll('.tp-table-select-btn');

function isSafeRelativePath(path) {
    if (typeof path !== 'string') {
        return false;
    }
    if (path.startsWith('//')) {
        return false;
    }
    if (path.startsWith('/')) {
        const firstSlashIndex = path.indexOf('/', 1);
        const prefix = firstSlashIndex === -1 ? path : path.slice(0, firstSlashIndex);
        if (prefix.includes(':')) {
            return false;
        }
    }
    if (path.includes(':')) {
        const colonIndex = path.indexOf(':');
        const beforeColon = path.slice(0, colonIndex);
        if (!beforeColon.includes('/')) {
            return false;
        }
    }
    return true;
}

checkboxColumn?.addEventListener('change', toggleAllCheckboxes);
if (checkboxColumn) {
    tableSelectButtons.forEach(function(el) {
        el.addEventListener('click', function(event) {
            const rawUrl = event.target.getAttribute('data-tp-url');
            if (!isSafeRelativePath(rawUrl)) {
                return;
            }
            
            const checkedIds = [];
            checkboxes.forEach(function(el) {
                if (el.checked && /^\d+$/.test(el.value)) {
                    checkedIds.push(el.value);
                }
            });
            
            try {
                const url = new URL(rawUrl + '/', window.location.href);
                
                checkedIds.forEach(function(id) {
                    url.pathname = url.pathname.replace(/\/$/, '') + '/' + encodeURIComponent(id);
                });
                
                if (!url.pathname.endsWith('/')) {
                    url.pathname += '/';
                }
                
                window.location.assign(url.pathname);
            } catch (e) {
                console.error('Invalid URL construction:', e);
            }
        })
    });
}


function toggleAllCheckboxes() {
    if (checkboxColumn.checked) {
        checkboxes.forEach(function(el) {
            el.checked = true;
        });
    } else {
        checkboxes.forEach(function(el) {
            el.checked = false;
        });
    }
}

// ---------------------------------------- Table Query update ----------------------------------------

function updateQueryParam(event, key, value) {
    event.preventDefault();
    const url = new URL(window.location);
    if (key == 'sort' && value == url.searchParams.get('sort')) {
        value = `-${value}`; // toggle to descending order
    }
    url.searchParams.set(key, value);
    window.location.href = url.toString();
}

// ---------------------------------------- Side nav menu toggling ----------------------------------------

function hideMenu() {
    document.querySelector('.tp-sidenav').classList.remove('sidenav-show');
    document.querySelector('#menu-icon-menu').classList.remove('d-none');
    document.querySelector('#menu-icon-back').classList.add('d-none');
}

function toggleMenu(event) {
    document.querySelector('.tp-sidenav').classList.toggle('sidenav-show');
    document.querySelector('#menu-icon-menu').classList.toggle('d-none');
    document.querySelector('#menu-icon-back').classList.toggle('d-none');
}

function setupMenuToggle() {
    document.querySelector('.menu-icon').addEventListener('click', toggleMenu);
    document.querySelector('.tp-main').addEventListener('click', hideMenu);
}

window.addEventListener('load', function(e) {
    setupMenuToggle();
});

// ---------------------------------------- Side nav submenu collapsing ----------------------------------------

// custom collapse implementation, since the one provided by Bootstrap does not allow preventing navigation

// add onclick event listener to all elements with btn-collapse class
const collapseButtons = document.querySelectorAll('.btn-collapse');
collapseButtons.forEach(function(button) {
    button.addEventListener('click', toggleCollapse);
    if (button.ariaExpanded === "true") {
        setMenuCollapsed(button, false); // to set explicit scroll height for CSS transition
    }
    // if the menu was manually expanded, keep it expanded upon navigation
    if (button.dataset.category && sessionStorage.getItem('tp-menu-expanded-manually-' + button.dataset.category) === 'true') {
        setMenuCollapsed(button, false, false);
    }
});

function setMenuCollapsed(btn, collapse=true, transition=true) {
    const target = btn?.parentElement.parentElement.querySelector('.tp-menu-collapse');
    if (!target) return;

    if (transition) {
        btn.classList.add('collapse-transition');
        target.classList.add('collapse-transition');
    } else {
        btn.classList.remove('collapse-transition');
        target.classList.remove('collapse-transition');
    }

    if (collapse) {
        btn.ariaExpanded = "false";
        target.style.height = '0px';
    } else {
        btn.ariaExpanded = "true";
        if (target.scrollHeight > 0)
            target.style.height = target.scrollHeight + 'px';
        else
            target.style.height = 'auto';
    }

    //target.style.transition = transition ? 'height 0.2s' : 'none';
}

function toggleCollapse(event) {
    // stop propagation to prevent the event from loading the page
    event.preventDefault();

    let collapse = this.ariaExpanded === "true";
    setMenuCollapsed(this, collapse);

    if (this.dataset.category) {
        sessionStorage.setItem('tp-menu-expanded-manually-' + this.dataset.category, !collapse);
    }
}

// ---------------------------------------- Certificate Download Format Options ----------------------------------------

const derSelect = document.querySelector('#id_cert_file_format > option[value=der]');
const certCount = document.querySelector('#cert-count');
const certFileContainerSelect = document.getElementById('id_cert_file_container');
const certChainInclSelect = document.getElementById('id_cert_chain_incl');
const certFileFormatSelect = document.getElementById('id_cert_file_format');

if (derSelect && certCount && certFileContainerSelect && certChainInclSelect && certFileFormatSelect) {
    togglePemSelectDisable()
    certFileContainerSelect.addEventListener('change', togglePemSelectDisable);
    certChainInclSelect.addEventListener('change', togglePemSelectDisable);
    certFileFormatSelect.addEventListener('change', togglePemSelectDisable);
}

function togglePemSelectDisable() {
    if (certChainInclSelect.value === 'chain_incl') {
        derSelect.disabled = true;
    } else derSelect.disabled = !(certCount.innerText !== '1' && certFileContainerSelect.value !== 'single_file');

    if (derSelect.disabled && certFileFormatSelect.value === 'der') {
            certFileFormatSelect.value = 'pem';
    }
}

// ------------------------------------------------- Device Creation --------------------------------------------------


const onboardingAndPkiConfigurationSelect = document.getElementById('id_onboarding_protocol');
const idevidTrustStoreSelectWrapper = document.getElementById('id_idevid_trust_store_select_wrapper');
const pkiProtocolEstSelect = document.getElementById('id_allowed_pki_protocols_0');
const pkiProtocolCmpSelect = document.getElementById('id_allowed_pki_protocols_1');

// const onboardingAndPkiConfigurationSelect = document.getElementById('id_onboarding_and_pki_configuration');

const domainCredentialOnboardingCheckbox = document.getElementById('id_domain_credential_onboarding');
const onboardingAndPkiConfigurationWrapper = document.getElementById('id_onboarding_protocol_wrapper');
const pkiConfigurationWrapper = document.getElementById('id_pki_configuration_wrapper');
const allowedPkiProtocolsHeader = document.getElementById('id_allowed_pki_protocols_header');
const allowedPkiProtocolsHr = document.getElementById('id_allowed_pki_protocols_hr');
const allowedPkiProtocolsWrapper = document.getElementById('id_allowed_pki_protocols_wrapper');

onboardingAndPkiConfigurationSelect?.addEventListener('change', function(event) {
   const selectedOptionValue = event.target.options[event.target.selectedIndex].value;
   console.log(selectedOptionValue);

    switch (selectedOptionValue) {
        case 'est_username_password':
            addClassIfNotPresent(idevidTrustStoreSelectWrapper, 'd-none');
            pkiProtocolEstSelect.checked = true;
            pkiProtocolCmpSelect.checked = false;
            break;
        case 'cmp_shared_secret':
            addClassIfNotPresent(idevidTrustStoreSelectWrapper, 'd-none');
            pkiProtocolEstSelect.checked = false;
            pkiProtocolCmpSelect.checked = true;
            break;
        case 'manual':
            addClassIfNotPresent(idevidTrustStoreSelectWrapper, 'd-none');
            pkiProtocolEstSelect.checked = true;
            pkiProtocolCmpSelect.checked = true;
            break;
        case 'est_idevid':
            removeClassIfPresent(idevidTrustStoreSelectWrapper, 'd-none');
            pkiProtocolEstSelect.checked = true;
            pkiProtocolCmpSelect.checked = false;
            break;
        case 'cmp_idevid':
            removeClassIfPresent(idevidTrustStoreSelectWrapper, 'd-none');
            pkiProtocolEstSelect.checked = false;
            pkiProtocolCmpSelect.checked = true;
            break;
    }
});

function handleOnboardingCheckbox(checked) {
    if (checked) {
        addClassIfNotPresent(pkiConfigurationWrapper, 'd-none');
        removeClassIfPresent(onboardingAndPkiConfigurationWrapper, 'd-none');
        removeClassIfPresent(allowedPkiProtocolsHeader, 'd-none');
        removeClassIfPresent(allowedPkiProtocolsHr, 'd-none');
        removeClassIfPresent(allowedPkiProtocolsWrapper, 'd-none');
    } else {
        removeClassIfPresent(pkiConfigurationWrapper, 'd-none');
        addClassIfNotPresent(onboardingAndPkiConfigurationWrapper, 'd-none');
        addClassIfNotPresent(allowedPkiProtocolsHeader, 'd-none');
        addClassIfNotPresent(allowedPkiProtocolsHr, 'd-none');
        addClassIfNotPresent(allowedPkiProtocolsWrapper, 'd-none');
    }
}

domainCredentialOnboardingCheckbox?.addEventListener('change', function(event) {
    handleOnboardingCheckbox(event.target.checked);
});

if (domainCredentialOnboardingCheckbox) {
    handleOnboardingCheckbox(domainCredentialOnboardingCheckbox.checked);
}

function addClassIfNotPresent(element, className) {
  if (!element.classList.contains(className)) {
    element.classList.add(className);
  }
}

function removeClassIfPresent(element, className) {
  if (element.classList.contains(className)) {
    element.classList.remove(className);
  }
}

// -------------------------------------------- Help Pages - Hidden Toggle ---------------------------------------------

let certProfileSelect = document.getElementById('cert-profile-select');
let sections = {};

if (certProfileSelect) {
    for (const option of certProfileSelect.options) {
        const el = document.getElementById(option.value);
        if (el) {
            sections[option.value] = el;
        }
    }
}

function displayOnly(sectionIdToDisplay) {
    for (const [id, el] of Object.entries(sections)) {
        if (id == sectionIdToDisplay) {
            el.removeAttribute('hidden');
        } else {
            el.setAttribute('hidden', '');
        }
    }
}

certProfileSelect?.addEventListener("change", function() {
    displayOnly(certProfileSelect.value);   
});
