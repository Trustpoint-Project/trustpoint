import {
  buildVariableSuggestions,
  renderVariableButtons,
} from './guide_ui_helpers.js';
import { renderConditionDsl } from './guide_dsl_sections.js';
import { renderConditionNode } from './guide_apply_condition_renderer.js';
import {
  renderGuideButtonRow,
  renderGuideSection,
} from './guide_layout.js';
import { parseApplyItems, renderButton } from './guide_apply_shared.js';

function renderApplyRule(rule, ruleIndex, isCurrent, catalog) {
  return `
    <div class="mb-3">
      <div class="fw-semibold mb-2">
        Apply rule ${ruleIndex + 1}${isCurrent ? ' · current' : ''}
      </div>

      ${renderConditionNode({
        catalog,
        ruleIndex,
        path: [],
        node: rule,
        isRoot: true,
        allowRemove: true,
        extraClass: isCurrent ? ' border-primary' : '',
      })}
    </div>
  `;
}

export function renderApplyGuide(context, catalog, yamlText = '') {
  const applyItems = parseApplyItems(yamlText);
  const currentRuleIndex =
    Array.isArray(context?.path) && typeof context.path[1] === 'number'
      ? context.path[1]
      : null;

  const { eventButtons, varsButtons } = buildVariableSuggestions(context, catalog);

  return `
    ${renderGuideSection({
      title: 'Apply rules',
      description: 'These conditions are evaluated before the workflow starts.',
      tone: 'accent',
      body: '',
    })}

    ${renderGuideSection({
      title: 'Add apply rule',
      description: 'Start with the operator that best matches the filter you need.',
      body: renderGuideButtonRow(`
        ${renderButton('add-apply-rule', 'Add compare', ' data-apply-operator="compare"')}
        ${renderButton('add-apply-rule', 'Add exists', ' data-apply-operator="exists"')}
        ${renderButton('add-apply-rule', 'Add not', ' data-apply-operator="not"')}
        ${renderButton('add-apply-rule', 'Add and', ' data-apply-operator="and"')}
        ${renderButton('add-apply-rule', 'Add or', ' data-apply-operator="or"')}
      `),
    })}

    ${renderGuideSection({
      title: 'Current apply rules',
      body: applyItems.length
        ? applyItems
            .map((rule, index) => renderApplyRule(rule, index, currentRuleIndex === index, catalog))
            .join('')
        : '<div class="small text-muted">No apply rules yet.</div>',
    })}

    ${renderGuideSection({
      title: 'Insert event variable',
      description: 'Insert at the current YAML cursor position.',
      body: renderGuideButtonRow(renderVariableButtons(eventButtons)),
    })}

    ${renderGuideSection({
      title: 'Insert workflow var',
      description: 'Insert at the current YAML cursor position.',
      body: renderGuideButtonRow(renderVariableButtons(varsButtons)),
    })}

    ${renderGuideSection({
      title: 'Condition reference',
      body: renderConditionDsl(catalog),
    })}
  `;
}
