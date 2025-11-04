// static/js/ui-triggers.js
// Renders the trigger selector (handler → protocol → operation) from state.triggersMap.
// Keeps state mutations via setHandler/setProtocol/setOperation and re-renders on changes.

import { state, setHandler, setProtocol, setOperation } from './state.js';

export function renderTriggersUI({ els, onChange }) {
  if (!els || !els.handlerEl || !els.protoEl || !els.opEl || !els.protoContainer || !els.opContainer) {
    return;
  }

  const norm = (s) => (s == null ? '' : String(s)).trim();
  const nproto = (s) => norm(s).toLowerCase();

  // Materialize triggers from map and pre-compute normalized protocol
  const mapValues = Object.values(state.triggersMap || {}).map((t) => ({
    handler: norm(t.handler),
    protocol: norm(t.protocol),
    protocol_lc: nproto(t.protocol),
    operation: norm(t.operation),
  }));

  const uniq = (arr) => [...new Set(arr)];
  const byHandler = (h) => (t) => norm(t.handler) === norm(h);
  const byHandlerProto = (h, pLc) => (t) =>
    norm(t.handler) === norm(h) && t.protocol_lc === nproto(pLc);

  // ---- Handlers ----
  const handlers = uniq(mapValues.map((t) => t.handler).filter(Boolean)).sort();
  els.handlerEl.innerHTML = '';
  handlers.forEach((h) => {
    const opt = new Option(h.replace(/_/g, ' '), h);
    if (h === state.handler) opt.selected = true;
    els.handlerEl.add(opt);
  });
  if (!state.handler && handlers.length) {
    setHandler(handlers[0]);
    els.handlerEl.value = state.handler;
  }

  // ---- Protocols (for selected handler) ----
  const relevant = mapValues.filter(byHandler(state.handler));
  const protosLc = uniq(relevant.map((t) => t.protocol_lc).filter(Boolean)).sort();

  if (protosLc.length) {
    els.protoContainer.style.display = '';
    els.protoEl.innerHTML = '';
    protosLc.forEach((p) => {
      // display as stored (lowercased), value is lowercased canonical
      const opt = new Option(p, p);
      if (p === nproto(state.protocol)) opt.selected = true;
      els.protoEl.add(opt);
    });
    if (!state.protocol || !protosLc.includes(nproto(state.protocol))) {
      setProtocol(protosLc[0]);
      els.protoEl.value = nproto(state.protocol);
    }
  } else {
    els.protoContainer.style.display = 'none';
    els.protoEl.innerHTML = '';
    setProtocol('');
  }

  // ---- Operations (for selected handler+protocol) ----
  const ops = uniq(
    mapValues
      .filter(byHandlerProto(state.handler, state.protocol))
      .map((t) => t.operation)
      .filter(Boolean)
  ).sort();

  if (ops.length) {
    els.opContainer.style.display = '';
    els.opEl.innerHTML = '';
    ops.forEach((o) => {
      const opt = new Option(o, o);
      if (o === state.operation) opt.selected = true;
      els.opEl.add(opt);
    });
    if (!state.operation || !ops.includes(state.operation)) {
      setOperation(ops[0]);
      els.opEl.value = state.operation;
    }
  } else {
    els.opContainer.style.display = 'none';
    els.opEl.innerHTML = '';
    setOperation('');
  }

  // ---- Wire events (assign, not addEventListener → avoids stacking) ----
  els.handlerEl.onchange = () => {
    setHandler(els.handlerEl.value);
    renderTriggersUI({ els, onChange });
    onChange();
  };
  els.protoEl.onchange = () => {
    setProtocol(els.protoEl.value); // value is canonical lowercased protocol
    renderTriggersUI({ els, onChange });
    onChange();
  };
  els.opEl.onchange = () => {
    setOperation(els.opEl.value);
    onChange();
  };
}