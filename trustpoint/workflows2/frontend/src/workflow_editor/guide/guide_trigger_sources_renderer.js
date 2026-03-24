import { escapeHtml } from '../shared/dom.js';
import { renderActionButton } from './guide_ui_helpers.js';
import {
  renderGuideButtonRow,
  renderGuideMeta,
  renderGuideNote,
  renderGuideSection,
} from './guide_layout.js';

function findSelectedEntry(entries, rawValue) {
  return (entries || []).find((entry) => String(entry?.id) === String(rawValue)) || null;
}

function renderSelectedItems({ title, sourceKind, selectedValues, entries }) {
  if (!Array.isArray(selectedValues) || !selectedValues.length) {
    return renderGuideNote(`No ${title.toLowerCase()} selected yet.`, 'muted');
  }

  return `
    <div class="wf2-source-selection-list">
      ${selectedValues
        .map((rawValue) => {
          const entry = findSelectedEntry(entries, rawValue);
          const label = entry?.title || String(rawValue);
          const meta = entry
            ? buildEntryMeta(entry, sourceKind)
            : 'Not found in current Trustpoint data';

          return `
            <div class="wf2-source-selected-item">
              <div>
                <div class="wf2-source-entry-title">${escapeHtml(label)}</div>
                <div class="wf2-source-entry-meta">${escapeHtml(meta)}</div>
              </div>
              ${renderActionButton(
                'remove-trigger-source-value',
                'Remove',
                ` data-trigger-source-kind="${escapeHtml(sourceKind)}" data-trigger-source-value="${escapeHtml(String(rawValue))}"`,
              )}
            </div>
          `;
        })
        .join('')}
    </div>
  `;
}

function buildEntryMeta(entry, sourceKind) {
  if (sourceKind === 'ca_ids') {
    const parts = [`ID ${entry.id}`];
    if (entry.type) {
      parts.push(entry.type);
    }
    if (entry.active === false) {
      parts.push('inactive');
    }
    return parts.join(' · ');
  }

  if (sourceKind === 'domain_ids') {
    const parts = [`ID ${entry.id}`];
    if (entry.issuing_ca_title) {
      parts.push(`CA ${entry.issuing_ca_title}`);
    }
    if (entry.active === false) {
      parts.push('inactive');
    }
    return parts.join(' · ');
  }

  const parts = [`ID ${entry.id}`];
  if (entry.domain_title) {
    parts.push(`Domain ${entry.domain_title}`);
  }
  if (entry.serial_number) {
    parts.push(`SN ${entry.serial_number}`);
  }
  return parts.join(' · ');
}

function renderAvailableEntries({ title, sourceKind, entries, selectedValues, placeholder }) {
  if (!Array.isArray(entries) || !entries.length) {
    return renderGuideNote(`No ${title.toLowerCase()} found in Trustpoint yet.`, 'muted');
  }

  return `
    <div class="wf2-source-group" data-wf2-source-group="true">
      <div class="wf2-source-toolbar">
        <input
          type="search"
          class="form-control form-control-sm"
          placeholder="${escapeHtml(placeholder)}"
          data-wf2-source-filter-input="true"
        />
      </div>

      <div class="wf2-source-list">
        ${entries
          .map((entry) => {
            const isSelected = (selectedValues || []).some((value) => String(value) === String(entry.id));
            const searchText = [entry.title, buildEntryMeta(entry, sourceKind)].filter(Boolean).join(' ').toLowerCase();

            return `
              <div
                class="wf2-source-entry${isSelected ? ' wf2-source-entry-selected' : ''}"
                data-wf2-source-entry="true"
                data-search-text="${escapeHtml(searchText)}"
              >
                <div class="wf2-source-entry-copy">
                  <div class="wf2-source-entry-title">${escapeHtml(entry.title || String(entry.id))}</div>
                  <div class="wf2-source-entry-meta">${escapeHtml(buildEntryMeta(entry, sourceKind))}</div>
                </div>
                <div class="wf2-source-entry-actions">
                  ${renderActionButton(
                    'add-trigger-source-value',
                    isSelected ? 'Selected' : 'Add',
                    ` data-trigger-source-kind="${escapeHtml(sourceKind)}" data-trigger-source-value="${escapeHtml(String(entry.id))}"${isSelected ? ' disabled' : ''}`,
                  )}
                </div>
              </div>
            `;
          })
          .join('')}
      </div>

      <div class="wf2-source-empty text-muted" data-wf2-source-empty-state="true" hidden>
        No matching ${escapeHtml(title.toLowerCase())}.
      </div>
    </div>
  `;
}

function renderSourceGroupSection({
  title,
  description,
  sourceKind,
  selectedValues,
  entries,
  currentFieldKey = null,
}) {
  const selectedCount = Array.isArray(selectedValues) ? selectedValues.length : 0;
  const fieldMap = {
    ca_ids: 'ca_ids',
    domain_ids: 'domain_ids',
    device_ids: 'device_ids',
  };

  return renderGuideSection({
    title,
    description,
    tone: currentFieldKey === fieldMap[sourceKind] ? 'accent' : 'default',
    body:
      renderGuideMeta([
        { label: 'Selected', value: String(selectedCount) },
        { label: 'Known', value: String((entries || []).length) },
      ]) +
      renderSelectedItems({ title, sourceKind, selectedValues, entries }) +
      renderAvailableEntries({
        title,
        sourceKind,
        entries,
        selectedValues,
        placeholder: `Filter ${title.toLowerCase()}`,
      }),
  });
}

export function renderTriggerSourcesGuide(context, catalog) {
  const currentSources = context?.currentTriggerSources || {
    trustpoint: false,
    caIds: [],
    domainIds: [],
    deviceIds: [],
  };

  const triggerSources = catalog?.trigger_sources || {
    cas: [],
    domains: [],
    devices: [],
  };

  const isTrustpointWide = Boolean(currentSources.trustpoint);

  return `
    ${renderGuideSection({
      title: 'Current trigger scope',
      description: 'Use trustpoint-wide mode for every source, or turn it off and explicitly target CA, domain, or device ids.',
      tone: isTrustpointWide ? 'accent' : 'default',
      body:
        renderGuideMeta([
          { label: 'Trustpoint-wide', value: isTrustpointWide ? 'Yes' : 'No' },
          { label: 'CA filters', value: String((currentSources.caIds || []).length) },
          { label: 'Domain filters', value: String((currentSources.domainIds || []).length) },
          { label: 'Device filters', value: String((currentSources.deviceIds || []).length) },
        ]) +
        renderGuideButtonRow(
          [
            renderActionButton(
              'set-trigger-trustpoint',
              'Trustpoint wide',
              ` data-trigger-trustpoint="true"${isTrustpointWide ? ' disabled' : ''}`,
            ),
            renderActionButton(
              'set-trigger-trustpoint',
              'Use explicit filters',
              ` data-trigger-trustpoint="false"${!isTrustpointWide ? ' disabled' : ''}`,
            ),
          ].join(''),
        ) +
        renderGuideNote(
          isTrustpointWide
            ? 'CA, domain, and device lists stay visible below, but they do not affect dispatch while trustpoint-wide is enabled.'
            : 'When trustpoint-wide is off, at least one CA, domain, or device id must be present.',
          isTrustpointWide ? 'info' : 'muted',
        ),
    })}

    ${renderSourceGroupSection({
      title: 'Certificate authorities',
      description: 'Insert CA ids into trigger.sources.ca_ids.',
      sourceKind: 'ca_ids',
      selectedValues: currentSources.caIds || [],
      entries: triggerSources.cas || [],
      currentFieldKey: context?.triggerSourceFieldKey || null,
    })}

    ${renderSourceGroupSection({
      title: 'Domains',
      description: 'Insert domain ids into trigger.sources.domain_ids.',
      sourceKind: 'domain_ids',
      selectedValues: currentSources.domainIds || [],
      entries: triggerSources.domains || [],
      currentFieldKey: context?.triggerSourceFieldKey || null,
    })}

    ${renderSourceGroupSection({
      title: 'Devices',
      description: 'Insert device ids into trigger.sources.device_ids.',
      sourceKind: 'device_ids',
      selectedValues: currentSources.deviceIds || [],
      entries: triggerSources.devices || [],
      currentFieldKey: context?.triggerSourceFieldKey || null,
    })}
  `;
}
