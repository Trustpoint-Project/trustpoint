import { state, addScopes, removeScope } from './state.js';
import { api } from './api.js';

export async function initScopesUI({typeEl, multiEl, addBtnEl, listEl, onChange}) {
  await loadChoices(typeEl.value, multiEl);

  typeEl.onchange = async () => {
    await loadChoices(typeEl.value, multiEl);
    // Note: preview is rendered by onChange() in main.js; do not call it twice here.
  };

  addBtnEl.onclick = () => {
    const ids = Array.from(multiEl.selectedOptions).map(o => o.value);
    addScopes(typeEl.value, ids);
    multiEl.selectedIndex = -1;
    renderList(listEl, onChange);
    onChange();
  };

  renderList(listEl, onChange);
}

async function loadChoices(kind, multiEl) {
  try {
    const list = await api.scopes(kind);

    // Keep the name cache for this kind deterministic.
    state.scopesChoices[kind].clear();
    list.forEach(it => state.scopesChoices[kind].set(String(it.id), it.name));

    // Populate the select
    multiEl.innerHTML = '';
    list.forEach(it => multiEl.add(new Option(it.name, it.id)));
  } catch {
    multiEl.innerHTML = '';
  }
}

function renderList(listEl, onChange) {
  listEl.textContent = '';
  const frag = document.createDocumentFragment();
  for (const kind of ['CA','Domain','Device']) {
    for (const id of state.scopes[kind]) {
      const li = document.createElement('li');
      li.className = 'list-group-item d-flex justify-content-between align-items-center';
      const name = state.scopesChoices[kind].get(String(id)) || String(id);
      li.textContent = `${kind}: ${name}`;
      const rm = document.createElement('button');
      rm.type = 'button'; rm.className = 'btn-close';
      rm.onclick = () => { removeScope(kind, id); renderList(listEl, onChange); onChange(); };
      li.appendChild(rm);
      frag.appendChild(li);
    }
  }
  listEl.appendChild(frag);
}
