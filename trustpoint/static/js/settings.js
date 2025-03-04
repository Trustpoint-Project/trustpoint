// ----- Security settings -----

var initialValues = {};


function prevalidateSecuritySettings() {
    // tests if the set advanced security settings are lower than the defaults of the set security level
    if (!document.querySelector('#security_configuration')) return; // only in security settings
    let sl = document.querySelector('input[name="security_mode"]:checked').value;
    // 0 = dev, 1 = basic, 2 = medium, 3 = high, 4 = highest
    if (sl < 0 || sl > 4) return; // invalid security level
    document.querySelector('#hidden_input_note').style.display = 'none';
    document.querySelector('#hidden_input_list').innerHTML = '';
    for (el of document.querySelectorAll('#security_configuration input, select')) {
        // hide settings that are not available for the selected security level
        if (el.dataset?.hideAtSl) {
            arr = JSON.parse(el.dataset.hideAtSl);
            if (arr[sl] === true) {
                document.querySelector('#hidden_input_note').style.display = 'block';
                let hiddenInput = document.createElement('li');
                labeltext = document.querySelector('label[for="' + el.id + '"]')?.innerText;
                hiddenInput.textContent = labeltext;
                document.querySelector('#hidden_input_list').appendChild(hiddenInput);
            }
            el.parentElement.style.display = (arr[sl] === true) ? 'none':'block';
        }
        if (!el.dataset?.slDefaults) continue;
        arr = JSON.parse(el.dataset.slDefaults);
        slDefault = arr[sl];
        value = el.value;
        if (el.type === 'checkbox') {
            value = el.checked ? 1 : 0;
        }
        if (value > slDefault && el.dataset.moreSecure === 'false' ||
            value < slDefault && el.dataset.moreSecure === 'true') {
            el.classList.add('mismatch');
            el.dataset.target = slDefault;
        } else {
            el.classList.remove('mismatch');
        }
    }
    renderMismatchWarning();
    renderAutoGenPkiDisableWarning();
}

function renderAutoGenPkiDisableWarning() {
    var willDisable = (document.querySelector('#id_auto_gen_pki').checked === false || 
                        document.querySelector('#id_auto_gen_pki').classList.contains('mismatch'));
    var showWarning = (willDisable && initialValues['auto_gen_pki'] === true)
    document.querySelector('#auto_gen_pki_disable_warning').style.display = showWarning ? 'flex': 'none';
}

function renderMismatchWarning() {
    let mismatches = document.querySelectorAll('#security_configuration .mismatch');
    let warning = document.querySelector('#mismatch_warning');
    if (mismatches.length > 0) {
        warning.style.display = 'flex';
        text = ngettext(
            'An advanced security setting is less secure than the selected security level permits.',
            'Some advanced security settings are less secure than the selected security level permits.', mismatches.length);
        text += '<ul>'
        for (el of mismatches) {
            labeltext = document.querySelector('label[for="' + el.id + '"]')?.innerText;
            more = el.dataset.moreSecure === 'true' ? gettext('at least ') : gettext('at most ');
            value = el.value;
            target = el.dataset.target;
            if (el.type === 'checkbox') {
                more = "";
                target = el.dataset.target == 1 ? gettext('enabled') : gettext('disabled');
                value = el.checked ? gettext('enabled') : gettext('disabled');
            }
            format = gettext("is %(is)s, but must be %(leastormost)s%(target)s");
            guide = interpolate(format, {is: value, leastormost: more, target: target}, true);
            text += '<li>' + labeltext + ' (' + guide + ')</li>';
        }
        text += '</ul>'	
        format = ngettext(
            'This setting will be changed on save to meet the desired security level %(lvl)s.',
            'These settings will be changed on save to meet the desired security level %(lvl)s.', mismatches.length);
        text += interpolate(format, {lvl: document.querySelector('input[name="security_mode"]:checked').labels[0].innerText}, true)
        // text += '<br><button class="btn btn-primary float-end" type="button" onclick="changeMismatchedSettings()">'
        // text += ngettext('Change', 'Change all', mismatches.length);
        // text += '</button>';
        document.querySelector('#mismatch_warning_text').innerHTML = text;
    } else {
        warning.style.display = 'none';
    }
}

// Add event listeners security settings form inputs and store initial values
for (el of document.querySelectorAll('#security_configuration input')) {
    el.addEventListener('change', prevalidateSecuritySettings);
    if (el.type === 'checkbox') {
        initialValues[el.name] = el.checked;
    } else if (el.type === 'radio') {
        if (el.checked) initialValues[el.name] = el.value;
    } else {
        initialValues[el.name] = el.value;
    }
}

prevalidateSecuritySettings();