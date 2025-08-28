import { state, setHandler, setProtocol, setOperation } from './state.js';

export function renderTriggersUI({els, onChange}) {
  // Build handlers
  const handlers = [...new Set(Object.values(state.triggersMap).map(t => t.handler))].filter(Boolean);
  els.handlerEl.innerHTML = '';
  handlers.forEach(h => {
    const label = h.replace(/_/g, ' ');
    const opt = new Option(label, h);
    if (h === state.handler) opt.selected = true;
    els.handlerEl.add(opt);
  });
  if (!state.handler && handlers.length) {
    setHandler(handlers[0]);
    els.handlerEl.value = state.handler;
  }

  // Build protocols for current handler
  const relevant = Object.values(state.triggersMap).filter(t => t.handler === state.handler);
  const protos = [...new Set(relevant.map(t => t.protocol).filter(Boolean))];
  if (protos.length) {
    els.protoContainer.style.display = '';
    els.protoEl.innerHTML = '';
    protos.forEach(p => {
      const opt = new Option(p, p);
      if (p === state.protocol) opt.selected = true;
      els.protoEl.add(opt);
    });
    if (!state.protocol) {
      setProtocol(protos[0]);
      els.protoEl.value = state.protocol;
    }
  } else {
    els.protoContainer.style.display = 'none';
    els.protoEl.innerHTML = '';
    setProtocol('');
  }

  // Build operations for (handler, protocol)
  const ops = Object.values(state.triggersMap)
    .filter(t => t.handler === state.handler && t.protocol === state.protocol)
    .map(t => t.operation)
    .filter(Boolean);
  if (ops.length) {
    els.opContainer.style.display = '';
    els.opEl.innerHTML = '';
    [...new Set(ops)].forEach(o => {
      const opt = new Option(o, o);
      if (o === state.operation) opt.selected = true;
      els.opEl.add(opt);
    });
    if (!state.operation) {
      setOperation(ops[0]);
      els.opEl.value = state.operation;
    }
  } else {
    els.opContainer.style.display = 'none';
    els.opEl.innerHTML = '';
    setOperation('');
  }

  // Wire events (assign, not addEventListener → avoids stacking)
  els.handlerEl.onchange = () => { setHandler(els.handlerEl.value); renderTriggersUI({els, onChange}); onChange(); };
  els.protoEl.onchange   = () => { setProtocol(els.protoEl.value);   renderTriggersUI({els, onChange}); onChange(); };
  els.opEl.onchange      = () => { setOperation(els.opEl.value);     onChange(); };
}
