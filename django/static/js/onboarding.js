function startPollingOnboardingState(urlExt, iconUrl) {
  // call getOnboardingState periodically
  setInterval(function() {getOnboardingState(urlExt, iconUrl)} , 2400);
  getOnboardingState(urlExt, iconUrl);
}

// Onboarding states, see onboarding/models.py
const
CONNECTION_ERROR = -4,
NO_SUCH_PROCESS = -3,
CANCELED = -2,
FAILED = -1,
STARTED = 0,
HMAC_GENERATED = 1,
TRUST_STORE_SENT = 2,
DEVICE_VALIDATED = 3,
LDEVID_SENT = 4,
COMPLETED = 5 // aka cert chain sent

function getOnboardingState(urlExt, iconUrl) {
  fetch('/api/onboarding/state/'+ urlExt)
    .then(response => response.json())
    .then(data => {
      console.log(data)
      let val = parseInt(data);
      if (Number.isInteger(val)) setOnboardingStateUI(val, iconUrl);
    }
  ).catch((error) => {
    setOnboardingStateUI(CONNECTION_ERROR, iconUrl);
  })
}

function setOnboardingStateUIElement(el, iconUrl, type, message, icon, extraClasses='') {
  el.className = `alert alert-${type} d-flex mt-3 ${extraClasses}`;

  el.innerHTML =
    `<svg class="bi flex-shrink-0 tp-msg-icon-margin" width="20" height="20" fill="currentColor" role="img" aria-label="State: "><use xlink:href="${iconUrl}#icon-${icon}"/></svg>
    <div>${message}</div>`;
}

function setOnboardingStateUI(state, iconUrl) {
  let type = 'info';
  let message = '';
  let icon = 'info-circle';
  let extraClasses = '';
  let navBack = false;
  let isDL = document.querySelector('#onboarding-state-dl');
  let isBrowerDetail = document.querySelector('#onboarding-state-bo');
  switch (state) {
    case STARTED:
      type = 'info';
      if (isBrowerDetail) {
        message = gettext('Waiting for browser client to connect...');
        icon = 'clock';
        extraClasses = 'breathing-anim';
      } else {
        message = gettext('Generating secrets...');
      }
      icon = 'clock';
      extraClasses = 'breathing-anim';
      break;
    case HMAC_GENERATED:
      type = 'info';
      message = gettext('Waiting for client to connect...');
      icon = 'clock';
      extraClasses = 'breathing-anim';
      break;
    case TRUST_STORE_SENT:
      type = 'info';
      message = gettext('<strong>Step 1/3</strong> Sent trust store to client. Waiting for CSR...');
      icon = 'clock';
      extraClasses = 'breathing-anim';

      var el = document.querySelector('#onboarding-state-1');
      if (!el) break;
      type1 = 'info';
      message1 = gettext('Trust store requested.');
      icon1 = 'info';
      setOnboardingStateUIElement(el, iconUrl, type1, message1, icon1);
      break;
    case DEVICE_VALIDATED:
      type = 'info';
      message = gettext('<strong>Step 2/3</strong> Device validated. Signing certificate...');
      icon = 'clock';
      extraClasses = 'breathing-anim';
      break;
    case LDEVID_SENT:
      if (isBrowerDetail) {
        type = 'success';
        message = gettext('Browser client connected, pending download.');
        icon = 'clock';
        extraClasses = 'breathing-anim';
      } else if (isDL) {
        type = 'success';
        message = gettext('PKCS12 ready for download.');
        icon = 'success';
      } else {
        type = 'info';
        message = gettext('<strong>Step 3/3</strong> Sent signed certificate to client. Waiting for certificate chain request...');
        icon = 'clock';
        extraClasses = 'breathing-anim';
      }
      var el = document.querySelector('#onboarding-state-2');
      if (!el) break;
      var type1 = 'success';
      var message1 = gettext('LDevID downloaded successfully.');
      var icon1 = 'success';
      setOnboardingStateUIElement(el, iconUrl, type1, message1, icon1);
      el = document.querySelector('#onboarding-state-3');
      if (!el) break;
      var type2 = 'secondary';
      var message2 = gettext('Certificate chain not requested yet.');
      var icon2 = 'clock';
      break;
    case COMPLETED:
      type = 'success';
      message = gettext('Onboarding completed successfully. Redirecting...');
      icon = 'success';
      navBack = true;
      break;
    case FAILED:
      type = 'danger';
      message = gettext('Error: Something went wrong during the onboarding process.');
      icon = 'error';
      navBack = true;
      break;
    case CANCELED:
      type = 'warning';
      message = gettext('Onboarding process was canceled.');
      icon = 'warning';
      navBack = true;
      break;
    case NO_SUCH_PROCESS:
      type = 'danger';
      message = gettext('Error: Server did not find the onboarding process.');
      icon = 'error';
      navBack = true;
      break;
    default:
      type = 'warning';
      message = gettext('Could not get onboarding state from server');
      icon = 'warning';
      break;
  }

  if (navBack) { window.location.href = parentUrl; }

  var el = document.querySelector('#onboarding-state');
  if (!el) el = document.querySelector('#onboarding-state-dl');
  if (!el) el = document.querySelector('#onboarding-state-bo');
  setOnboardingStateUIElement(el, iconUrl, type, message, icon, extraClasses);
}

function resetButton(caller, short=false) {
  caller.classList.remove('btn-success');
  caller.classList.remove('btn-danger');
  caller.classList.add('btn-primary');
  caller.textContent = gettext(short ? 'Copy': 'Copy to clipboard');
}

async function copyToClipboard(caller, el, short=false) {
  caller.classList.remove('btn-primary');
  try {
    await navigator.clipboard.writeText(document.querySelector(el).textContent);
    caller.classList.add('btn-success');
    caller.textContent = gettext('Copied!');
  } catch (error) {
    caller.classList.add('btn-danger');
    caller.textContent = gettext("Couldn't copy");
  }
  setTimeout(resetButton, 1200, caller, short);
}

if (url) startPollingOnboardingState(url, icons);