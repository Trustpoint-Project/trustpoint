/* Copyright (c) 2026 The Trustpoint Project Authors; SPDX-License-Identifier: MIT */
/* Dashboard: tab navigation, overview, notifications, security and analytics. */

// Use the same strftime pattern and timezone as the server's user date formatter.
const formatDashboardDate = (() => {
  const root = document.getElementById('dashboard');
  const pattern = root?.dataset.dateFormat || '%Y-%m-%d %H:%M:%S';
  const timeZone = root?.dataset.timezone || 'UTC';
  const formatter = new Intl.DateTimeFormat('en-US', {
    timeZone, year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23'
  });
  const monthFormatter = /%[bB]/.test(pattern) ? new Intl.DateTimeFormat('en-US', {
    timeZone, month: pattern.includes('%b') ? 'short' : 'long'
  }) : null;
  return value => {
    if (!value) return '';
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) return '';
    const parts = Object.fromEntries(formatter.formatToParts(date).map(part => [part.type, part.value]));
    const hour = Number(parts.hour);
    const tokens = {
      '%Y': parts.year.padStart(4, '0'), '%m': parts.month, '%d': parts.day,
      '%H': parts.hour, '%M': parts.minute, '%S': parts.second,
      '%I': String(hour % 12 || 12).padStart(2, '0'), '%p': hour < 12 ? 'AM' : 'PM',
      '%b': monthFormatter?.format(date), '%B': monthFormatter?.format(date)
    };
    return pattern.replace(/%[YmdHMSIpbB]/g, token => tokens[token]);
  };
})();

// Tab navigation is independent of API fetches.
  (function () {
    'use strict';
    const root = document.getElementById('dashboard');
    if (!root) return;
    const panelIds = {
      overview: 'dashboard-overview',
      certificates: 'dashboard-certificates',
      devices: 'dashboard-devices-panel',
      cas: 'dashboard-cas-panel'
    };
    const buttons = Array.from(root.querySelectorAll('[data-dashboard-tab]'));
    const panels = Object.fromEntries(
      Object.entries(panelIds).map(([name, id]) => [name, document.getElementById(id)])
    );

    function activate(name, save = true) {
      if (!Object.prototype.hasOwnProperty.call(panelIds, name)) name = 'overview';
      buttons.forEach(button => {
        const selected = button.dataset.dashboardTab === name;
        button.classList.toggle('is-active', selected);
        button.setAttribute('aria-selected', String(selected));
        button.setAttribute('tabindex', selected ? '0' : '-1');
      });
      Object.entries(panels).forEach(([key, panel]) => {
        if (panel) panel.hidden = key !== name;
      });
      root.dataset.activeTab = name;
      const detailControls = document.getElementById('dashboard-detail-controls');
      if (detailControls) detailControls.hidden = name === 'overview' || name === 'devices';
      if (save) {
        root.dispatchEvent(new CustomEvent('dashboard:tab-changed', {detail:{tab:name}}));
        try { localStorage.setItem('trustpoint.dashboard.tab', name); } catch (_) { /* storage optional */ }
      }
    }
    // Use delegated clicks, so an unrelated JS exception cannot disable navigation.
    root.querySelector('.dashboard-tabs').addEventListener('click', event => {
      const button = event.target.closest('[data-dashboard-tab]');
      if (button && root.contains(button)) activate(button.dataset.dashboardTab);
    });
    root.querySelector('.dashboard-tabs').addEventListener('keydown', event => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      const current = buttons.indexOf(document.activeElement);
      if (current < 0) return;
      event.preventDefault();
      const next = event.key === 'Home' ? 0 : event.key === 'End' ? buttons.length - 1 :
        (current + (event.key === 'ArrowRight' ? 1 : -1) + buttons.length) % buttons.length;
      activate(buttons[next].dataset.dashboardTab);
      buttons[next].focus();
    });
    let initial = 'overview';
    try { initial = localStorage.getItem('trustpoint.dashboard.tab') || 'overview'; } catch (_) { /* storage optional */ }
    activate(initial, false);
    root.dataset.activeTab = initial;
  })();


/* Copyright (c) 2026 The Trustpoint Project Authors; SPDX-License-Identifier: MIT */
(() => {
  'use strict';
  const root = document.getElementById('dashboard');
  if (!root) return;
  const endpoint = root.dataset.overviewUrl;
  const notificationsEndpoint = root.dataset.notificationsUrl;
  const activityDays = document.getElementById('dashboard-activity-days');
  const horizon = document.getElementById('dashboard-expiry-days');
  const freshness = document.getElementById('dashboard-freshness');
  const colors = {valid:'#198754',expiring:'#e1a12c',expired:'#dc3545',revoked:'#7657a6',not_yet_valid:'#6c757d'};
  const labels = {valid:'Valid',expiring:'Expiring',expired:'Expired',revoked:'Revoked',not_yet_valid:'Not yet valid'};
  const keys = Object.keys(labels);
  let inFlight = null;
  let lastSuccess = null;

  function renderNotifications(data) {
    const counts = data.alerts.counts;
    document.getElementById('dashboard-alerts-counts').textContent =
      `${counts.critical} Critical · ${counts.warning} Warning · ${data.alerts.total} open`;
    function fillList(id, items, emptyText) {
      const list = document.getElementById(id);
      list.replaceChildren();
      if (!items.length) { const p = document.createElement('p'); p.className='text-body-secondary mb-0'; p.textContent=emptyText; list.append(p); return; }
      items.forEach(item => {
        const a = document.createElement('a'); a.className='list-group-item list-group-item-action';
        // Links come from the same-origin Django reverse() output, never from the notification body.
        const url = new URL(item.url, window.location.origin);
        if (url.origin !== window.location.origin) return;
        a.href=url.pathname+url.search;
        const label=document.createElement('div'); label.className='fw-semibold'; label.textContent=item.title;
        const info=document.createElement('small'); info.className='text-body-secondary';
        info.textContent=`${item.source}${item.associated_object ? ' · '+item.associated_object : ''} · ${formatDashboardDate(item.created_at)}`;
        a.append(label,info);list.append(a);
      });
    }
    fillList('dashboard-alerts-list',data.alerts.items,'No unresolved critical or warning notifications.');
    fillList('dashboard-activity-list',data.activity.items,'No Info or Setup notifications in this period.');

  }

  let notificationsInFlight = null;
  async function refreshNotifications() {
    if (notificationsInFlight) notificationsInFlight.abort();
    const req = new AbortController(); notificationsInFlight=req;
    try {
      const url=new URL(notificationsEndpoint, window.location.href);
      url.searchParams.set('activity_days',activityDays.value);
      const response=await fetch(url,{signal:req.signal,credentials:'same-origin',headers:{Accept:'application/json'}});
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data=await response.json();
      if(req===notificationsInFlight && data.alerts && data.activity) renderNotifications(data);
    } catch (e) {
      if(e.name!=='AbortError') document.getElementById('dashboard-alerts-counts').textContent='Notification data unavailable or stale';
    } finally {if(req===notificationsInFlight) notificationsInFlight=null;}
  }

  function render(data) {
    const c = data.certificates;
    document.getElementById('dashboard-total').textContent = c.total;
    document.getElementById('dashboard-expiring').textContent = c.expiring;
    document.getElementById('dashboard-expiring-label').textContent = `Expiring in ${data.expiry_days} days`;
    document.getElementById('dashboard-devices').textContent = data.devices.managed;
    document.getElementById('dashboard-cas').textContent = data.issuing_cas.enabled;
    document.getElementById('dashboard-devices-detail').textContent = data.devices.managed;
    document.getElementById('dashboard-cas-detail').textContent = data.issuing_cas.enabled;
    const breakdown=document.getElementById('dashboard-certs-breakdown');
    breakdown.replaceChildren();
    keys.forEach(key=>{
      const outer=document.createElement('div');outer.className='col-6 col-lg';
      const tile=document.createElement('div');tile.className='dashboard-health-tile h-100';
      const label=document.createElement('div');label.className='dashboard-health-title text-body-secondary';label.textContent=labels[key];
      const value=document.createElement('div');value.className='dashboard-health-value';value.textContent=String(c[key]);
      tile.style.borderTop=`4px solid ${colors[key]}`;tile.append(label,value);outer.append(tile);breakdown.append(outer);
    });
    const bar = document.getElementById('dashboard-health-bar');
    const legend = document.getElementById('dashboard-health-legend');
    bar.replaceChildren(); legend.replaceChildren();
    keys.forEach(key => {
      const part = Number(c[key]) || 0;
      if (part > 0) {
        const segment = document.createElement('span');
        segment.style.flex = `${part} 1 0`;
        segment.style.background = colors[key];
        segment.title = `${labels[key]}: ${part}`;
        bar.appendChild(segment);
      }
      const entry = document.createElement('span');
      entry.textContent = `${labels[key]}: ${part}`;
      entry.style.borderLeft = `8px solid ${colors[key]}`;
      entry.style.paddingLeft = '8px';
      legend.appendChild(entry);
    });
    document.getElementById('dashboard-health-note').textContent = c.unclassified
      ? `${c.unclassified} certificate(s) not classified; review invalid validity records.`
      : `${c.total} certificates classified as of ${formatDashboardDate(data.as_of)}.`;
    bar.setAttribute('aria-label', keys.map(k => `${labels[k]} ${c[k]}`).join(', '));
    lastSuccess = new Date();
    freshness.textContent = `Updated ${formatDashboardDate(lastSuccess)}`;
  }

  function updateExpiryLinks() {
    const url = new URL(root.dataset.certificateListUrl, window.location.origin);
    url.searchParams.set('status', 'ok');
    url.searchParams.set('expiry_window', `${horizon.value}_days`);
    const href = url.pathname + url.search;
    document.getElementById('dashboard-expiring-card').href = href;
    const detailLink = document.getElementById('dashboard-expiring-link');
    detailLink.href = href;
    detailLink.textContent = `View certificates expiring in ${horizon.value} days`;
  }

  async function refresh() {
    updateExpiryLinks();
    if (inFlight) inFlight.abort();
    const request = new AbortController();
    inFlight = request;
    freshness.textContent = 'Refreshing...';
    try {
      const url = new URL(endpoint, window.location.href);
      url.searchParams.set('expiry_days', horizon.value);
      const response = await fetch(url, {signal: request.signal, headers: {'Accept':'application/json'}, credentials:'same-origin'});
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      if (request !== inFlight) return;
      if (!data.certificates || typeof data.certificates.total !== 'number') throw new Error('Invalid payload');
      render(data);
    } catch (error) {
      if (error.name !== 'AbortError') {
        freshness.textContent = lastSuccess ? `Stale data — last updated ${formatDashboardDate(lastSuccess)}` : 'Data unavailable';
      }
    } finally {
      if (inFlight === request) inFlight = null;
    }
  }
  // Tab interactions are handled by the navigation block above.
  try { const saved = window.localStorage.getItem('trustpoint.dashboard.expiry_days'); if (['7','30','90'].includes(saved)) horizon.value = saved; } catch (_) { /* storage unavailable */ }
  horizon.addEventListener('change', () => { try { window.localStorage.setItem('trustpoint.dashboard.expiry_days', horizon.value); } catch (_) { /* optional */ } refresh(); });
  try { const saved=localStorage.getItem('trustpoint.dashboard.activity_days'); if(['7','30','90'].includes(saved)) activityDays.value=saved; } catch (_) { /* optional */ }
  activityDays.addEventListener('change',()=>{try{localStorage.setItem('trustpoint.dashboard.activity_days',activityDays.value);}catch(_){} refreshNotifications();});
  document.getElementById('dashboard-refresh').addEventListener('click', () => { refresh(); refreshNotifications(); });
  window.setInterval(()=>{if(!document.hidden)refreshNotifications();},60*1000);
  window.setInterval(() => { if (!document.hidden) refresh(); }, 5 * 60 * 1000);
  refresh();
  refreshNotifications();
})();

// Additional read-only TLS and crypto-provider indicators.
(() => {
  const root = document.getElementById('dashboard');
  const host = document.getElementById('dashboard-security-indicators');
  if (!root || !host) return;
  const card = (title, value, detail, href) => {
    const outer = document.createElement('div'); outer.className = 'col-12 col-md-4';
    const node = document.createElement('a');
    node.className = 'border rounded p-3 h-100 d-block text-body text-decoration-none dashboard-security-card';
    node.href = href;
    node.setAttribute('aria-label', `${title}: ${value}. Open settings`);
    const heading = document.createElement('div'); heading.className = 'fw-semibold'; heading.textContent = title;
    const main = document.createElement('div'); main.className = 'fs-5'; main.textContent = value;
    const desc = document.createElement('div'); desc.className = 'small text-body-secondary'; desc.textContent = detail;
    const action = document.createElement('div'); action.className = 'small text-primary mt-2'; action.textContent = 'Open settings ↗';
    node.append(heading, main, desc, action); outer.append(node); return outer;
  };
  async function refresh() {
    try {
      const response = await fetch(root.dataset.securityUrl, {credentials:'same-origin',headers:{Accept:'application/json'}});
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      const tls = data.tls_certificate;
      const detail = tls.expires_at ? `Expires ${formatDashboardDate(tls.expires_at)} · ${tls.days_remaining} days remaining` : 'No active TLS certificate found';
      host.replaceChildren(
        card('Active TLS certificate', tls.state.replaceAll('_',' '), detail, root.dataset.tlsSettingsUrl),
        card('Crypto backend', data.crypto_backend.kind, `Last capability probe: ${data.crypto_backend.probe_status}`, root.dataset.cryptoSettingsUrl),
        card('Security configuration', data.security_config?.label || 'Not configured', 'Configured security mode (not a security score)', root.dataset.securitySettingsUrl)
      );
    } catch (error) {host.textContent = `Security indicators unavailable (${error.message}).`;}
  }
  refresh();
  document.getElementById('dashboard-refresh')?.addEventListener('click', refresh);
})();


/* Copyright (c) 2026 The Trustpoint Project Authors; SPDX-License-Identifier: MIT */
(() => {
  'use strict';
  const root = document.getElementById('dashboard');
  if (!root) return;
  const url = root.dataset.analyticsUrl;
  const select = document.getElementById('dashboard-detail-activity-days');
  const expiry = document.getElementById('dashboard-detail-expiry-days');
  const names = {
    by_profile:'Certificates by profile (period)',
    by_issuing_ca:'Certificates issued by CA (period)',
    by_status:'Certificates by status',
    by_enrollment:'Devices by Enrollment Status',
    by_domain_credential:'Domain Credentials · Onboarding Devices',
    by_application_certificate:'Application Certificates · All Devices',
    by_protocol:'Enrollment Protocols · Onboarding Devices',
    by_domain:'Devices by domain', expiring_domain_credentials:'Expiring Domain Credentials · Onboarding Devices',
    status:'Issuing CA Status', signature_suites:'Issuing CA Signature Suites', ca_types:'CA Configuration Types', crl_freshness:'Active CRL Freshness'
  };
  const labels = {
    expiring_within_selected_horizon: 'Expiring within selected horizon',
    no_onboarding: 'Without onboarding', pending: 'Pending onboarding', onboarded: 'Onboarded',
    total: 'Total devices', none: 'None', valid: 'Valid', active: 'Active', expiring: 'Expiring',
    expired: 'Expired', expired_or_revoked_only: 'Only expired/revoked certificates',
    revoked: 'Revoked', not_yet_valid: 'Not yet valid', disabled: 'Disabled',
    no_certificate: 'No CA certificate',
    no_domain_credential: 'No domain credential',
    expiring_in_1_day: 'Expiring within 24 hours',
    expiring_in_7_days: 'Expiring in 1–7 days',
    expiring_in_30_days: 'Expiring in 8–30 days',
    not_yet_valid: 'Not yet valid',
    expiring_within_selected_horizon: 'Expiring within selected horizon',
    no_onboarding: 'Without onboarding',
    pending: 'Onboarding pending',
    onboarded: 'Onboarded',
    none: 'No application certificate',
    expired_or_revoked_only: 'Only expired or revoked certificates',
    active: 'Active / valid',
    expiring: 'Expiring soon',
    expired: 'Expired',
    disabled: 'Disabled', current: 'Up to date', missing: 'No active CRL', not_yet_valid: 'Not yet valid', no_certificate: 'Missing CA certificate',
  };
  const readable = text => labels[text] || String(text).replaceAll('_', ' ').replace(/\b\w/g, c=>c.toUpperCase());
  const tabs = new Set(['certificates','devices','cas']);
  let controller = null;
  function rows(value) {
    if (Array.isArray(value)) return value.map((x, i) => {
      if (x && typeof x === 'object') {
        const count = x.cert_count ?? x.device_count ?? x.onboarded_device_count ?? x.count ?? x.total;
        const name = x.ca_name ?? x.domain_name ?? x.name ?? x.protocol ?? x.label ?? `Group ${i+1}`;
        return {label:readable(name), count:Number(count), domainId:x.domain_id ?? null};
      }
      return {label:String(i+1), count:Number(x), domainId:null};
    }).filter(x=>Number.isFinite(x.count));
    if (value && typeof value==='object') return Object.entries(value).filter(([,v])=>typeof v==='number' && Number.isFinite(v)).map(([k,v])=>({label:readable(k),count:v,domainId:null,key:k}));
    return [];
  }
  function render(tab, data) {
    const host = document.getElementById('dashboard-analytics-'+tab);
    if (!host) return;
    host.replaceChildren();

    Object.entries(data.groups).forEach(([groupKey, group]) => {
      const outer=document.createElement('div');outer.className='col-12 col-xl-6';
      const card=document.createElement('div');card.className='card h-100';
      const body=document.createElement('div');body.className='card-body';
      const heading=document.createElement('h3');heading.className='h6'; heading.textContent=names[groupKey]||groupKey;body.append(heading);
      const values=rows(group).sort((a,b)=>b.count-a.count);
      const nonzero = values.filter(item=>item.count>0);
      const displayValues = (groupKey==='by_profile'||groupKey==='by_issuing_ca'||groupKey==='by_protocol') ? nonzero : values;
      if (!displayValues.length) {const p=document.createElement('p');p.className='text-body-secondary small';p.textContent='No matching records in the selected period';body.append(p);}
      const maximum=Math.max(1,...displayValues.map(x=>x.count));
      displayValues.slice(0,12).forEach(({label,count,domainId,key})=>{
        const line=document.createElement('div');line.className='mb-2';
        const meta=document.createElement('div');meta.className='d-flex justify-content-between small gap-2';
        const title=document.createElement('span');
        const linkUrl = (() => {
          if (tab === 'devices' && groupKey === 'by_enrollment' && ['no_onboarding', 'pending', 'onboarded'].includes(key)) {
            const target = new URL(root.dataset.deviceListUrl, location.href);
            target.searchParams.set('enrollment_state', key);
            return target.href;
          }
          if (tab === 'devices' && groupKey === 'by_domain' && domainId !== null) {
            const target = new URL(root.dataset.deviceListUrl, location.href);
            target.searchParams.set('domain', String(domainId));
            return target.href;
          }
          return null;
        })();
        if (linkUrl) {
          const link = document.createElement('a'); link.href = linkUrl;
          link.textContent = label; link.className = 'link-primary';
          link.setAttribute('aria-label', groupKey === 'by_enrollment'
            ? `Show devices: ${label}`
            : `Show devices in domain ${label}`);
          title.append(link);
        } else title.textContent=label;
        const number=document.createElement('strong');number.textContent=String(count);meta.append(title,number);
        const track=document.createElement('div');track.className='progress mt-1';track.style.height='8px';
        const bar=document.createElement('div');bar.className='progress-bar';bar.style.width=`${Math.max(0,Math.min(100,count/maximum*100))}%`;bar.setAttribute('aria-label',`${label}: ${count}`);track.append(bar);
        line.append(meta,track);body.append(line);
      });
      if (displayValues.length>12) {const p=document.createElement('p');p.className='small text-body-secondary';p.textContent=`Showing 12 of ${displayValues.length} groups`;body.append(p);}
      card.append(body);outer.append(card);host.append(outer);
    });
  }
  async function load(tab) {
    if (!tabs.has(tab)) return;
    if(controller) controller.abort();
    const request=new AbortController();controller=request;
    const host=document.getElementById('dashboard-analytics-'+tab);
    host.textContent='Loading analytics…';
    try {
      const endpoint=new URL(url,location.href);endpoint.searchParams.set('tab',tab);endpoint.searchParams.set('activity_days',select.value);endpoint.searchParams.set('expiry_days',expiry.value);
      const response=await fetch(endpoint,{signal:request.signal,credentials:'same-origin',headers:{Accept:'application/json'}});
      if(!response.ok)throw new Error(`HTTP ${response.status}`);
      const data=await response.json();
      if(controller===request)render(tab,data);
    } catch(error) { if(error.name!=='AbortError')host.textContent=`Analytics unavailable (${error.message}).`; }
    finally {if(controller===request)controller=null;}
  }
  root.addEventListener('dashboard:tab-changed', e=>load(e.detail.tab));
  select.addEventListener('change',()=>load(root.dataset.activeTab));
  expiry.addEventListener('change',()=>{const overview=document.getElementById('dashboard-expiry-days'); overview.value=expiry.value; overview.dispatchEvent(new Event('change'));});
  document.getElementById('dashboard-expiry-days').addEventListener('change',e=>{expiry.value=e.target.value;document.getElementById('dashboard-device-expiry-days').value=e.target.value;load(root.dataset.activeTab);});
  document.getElementById('dashboard-activity-days').addEventListener('change',e=>{select.value=e.target.value;load(root.dataset.activeTab);});
  document.getElementById('dashboard-refresh').addEventListener('click',()=>load(root.dataset.activeTab));
  document.getElementById('dashboard-device-expiry-days').addEventListener('change', e => {document.getElementById('dashboard-expiry-days').value=e.target.value;document.getElementById('dashboard-expiry-days').dispatchEvent(new Event('change'));});
  expiry.value=document.getElementById('dashboard-expiry-days').value;
  select.value=document.getElementById('dashboard-activity-days').value;
  document.getElementById('dashboard-device-expiry-days').value=expiry.value;
  load(root.dataset.activeTab);
})();
