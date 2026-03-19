import { escapeHtml, renderChips } from '../../core/dom.js';
import {
  findStepSpec,
  renderActionButton,
  renderScalarSetterButtons,
} from './helpers.js';

function findFieldMeta(catalog, context) {
  if (!context?.stepType || !context?.fieldKey) {
    return null;
  }

  const commonFields = catalog?.meta?.common_step_fields || [];
  const stepSpec = findStepSpec(catalog, context.stepType);
  const specificFields = stepSpec?.fields || [];

  return [...commonFields, ...specificFields].find((field) => field.key === context.fieldKey) || null;
}

function uniqStrings(values) {
  const out = [];
  const seen = new Set();

  for (const value of values || []) {
    if (typeof value !== 'string' || !value.trim()) {
      continue;
    }
    const s = value.trim();
    if (!seen.has(s)) {
      seen.add(s);
      out.push(s);
    }
  }

  return out;
}

function renderOutcomeSetterButtons(context) {
  const fromCurrentStep =
    context?.stepId
      ? context.stepSummaries?.find((item) => item.id === context.stepId)?.outcomes || []
      : [];

  const allKnown = uniqStrings([
    ...fromCurrentStep,
    ...(context?.stepSummaries || []).flatMap((item) => item.outcomes || []),
    'ok',
    'fail',
    'approved',
    'rejected',
    'needs_approval',
  ]);

  return renderScalarSetterButtons(allKnown);
}

export function renderConditionOperatorButtons(catalog, mode) {
  const operators = catalog?.dsl?.conditions?.operators || [];
  if (!operators.length) {
    return '<span class="text-muted">None</span>';
  }

  return (
    `<div class="d-flex flex-wrap gap-2">` +
    operators
      .map((op) =>
        renderActionButton(
          'insert-condition-operator',
          op.key,
          ` data-condition-key="${escapeHtml(op.key)}" data-condition-mode="${escapeHtml(mode)}" title="${escapeHtml(op.description || '')}"`,
        ),
      )
      .join('') +
    `</div>`
  );
}

export function renderExpressionFunctionButtons(catalog) {
  const groups = catalog?.dsl?.expressions?.function_groups || [];
  const allFunctions = groups.flatMap((group) => group.functions || []);

  if (!allFunctions.length) {
    return '<span class="text-muted">None</span>';
  }

  return (
    `<div class="d-flex flex-wrap gap-2">` +
    allFunctions
      .map((fn) =>
        renderActionButton(
          'insert-expression-function',
          fn.name,
          ` data-function-name="${escapeHtml(fn.name)}" title="${escapeHtml(fn.description || '')}"`,
        ),
      )
      .join('') +
    `</div>`
  );
}

export function renderComputeOperatorButtons(catalog) {
  const operators = catalog?.dsl?.compute?.operators || [];
  if (!operators.length) {
    return '<span class="text-muted">None</span>';
  }

  return (
    `<div class="d-flex flex-wrap gap-2">` +
    operators
      .map((op) =>
        renderActionButton(
          'insert-compute-operator',
          op,
          ` data-compute-op="${escapeHtml(op)}"`,
        ),
      )
      .join('') +
    `</div>`
  );
}

export function renderExpressionDsl(catalog, { insertableFunctions = false } = {}) {
  const refRoots = catalog?.dsl?.expressions?.ref_roots || [];
  const groups = catalog?.dsl?.expressions?.function_groups || [];

  return `
    <div class="mb-2">
      <div class="fw-semibold mb-1">Documented runtime namespaces</div>
      <div>${renderChips(refRoots, (root) => `<span class="wf2-chip"><strong>${escapeHtml(root)}.*</strong></span>`)}</div>
    </div>

    <div>
      <div class="fw-semibold mb-1">Expression functions</div>
      ${
        insertableFunctions
          ? renderExpressionFunctionButtons(catalog)
          : groups
              .map(
                (group) => `
          <div class="mb-2">
            <div class="text-muted mb-1">${escapeHtml(group.group)}</div>
            <div>${renderChips(group.functions || [], (fn) => {
              return (
                `<span class="wf2-chip" title="${escapeHtml(fn.description || '')}">` +
                `<strong>${escapeHtml(fn.name)}</strong>` +
                `</span>`
              );
            })}</div>
          </div>
        `,
              )
              .join('')
      }
    </div>
  `;
}

export function renderConditionDsl(catalog, { insertMode = null } = {}) {
  const operators = catalog?.dsl?.conditions?.operators || [];
  const compareOps = catalog?.dsl?.conditions?.compare_operators || [];

  return `
    <div class="mb-2">
      <div class="fw-semibold mb-1">Condition operators</div>
      ${
        insertMode
          ? renderConditionOperatorButtons(catalog, insertMode)
          : `<div>${renderChips(operators, (op) => {
              return (
                `<span class="wf2-chip" title="${escapeHtml(op.description || '')}">` +
                `<strong>${escapeHtml(op.key)}</strong>` +
                `</span>`
              );
            })}</div>`
      }
    </div>

    <div>
      <div class="fw-semibold mb-1">Compare operators</div>
      ${renderScalarSetterButtons(compareOps, (value) => `"${value}"`)}
    </div>
  `;
}

export function renderComputeDsl(catalog, { insertable = false } = {}) {
  const operators = catalog?.dsl?.compute?.operators || [];

  return `
    <div class="mb-2">
      <div class="fw-semibold mb-1">Compute YAML operators</div>
      ${
        insertable
          ? renderComputeOperatorButtons(catalog)
          : `<div>${renderChips(operators, (op) => `<span class="wf2-chip"><strong>${escapeHtml(op)}</strong></span>`)}</div>`
      }
    </div>

    ${renderExpressionDsl(catalog, { insertableFunctions: insertable })}
  `;
}

export function renderFieldSpecificOptions(catalog, context) {
  const fieldMeta = findFieldMeta(catalog, context);
  if (!fieldMeta) {
    return '';
  }

  switch (fieldMeta.field_kind) {
    case 'template':
    case 'text':
      return renderExpressionDsl(catalog, { insertableFunctions: true });

    case 'condition':
      return renderConditionDsl(catalog, { insertMode: 'mapping' });

    case 'condition_list':
      return renderConditionDsl(catalog, { insertMode: 'apply-item' });

    case 'compare_operator':
      return renderScalarSetterButtons(fieldMeta.enum || [], (value) => `"${value}"`);

    case 'http_method':
      return renderScalarSetterButtons(fieldMeta.enum || []);

    case 'outcome':
      return renderOutcomeSetterButtons(context);

    case 'compute_mapping':
      return renderComputeDsl(catalog, { insertable: true });

    case 'capture_mapping':
      return `
        <div class="mb-2">
          <div class="fw-semibold mb-1">Capture sources</div>
          ${renderScalarSetterButtons(
            ['status_code', 'body', 'headers', 'headers.x-request-id', 'body.some_value'],
          )}
        </div>
      `;

    default:
      return '';
  }
}