function readValue(scope, selector) {
  return scope?.querySelector(selector)?.value ?? '';
}

function readDirectChildNodes(container) {
  return [...(container?.children || [])].filter((child) =>
    child.classList?.contains('wf2-logic-tree-node'),
  );
}

function readLogicConditionNode(nodeEl) {
  const kind = readValue(nodeEl, '[data-condition-kind-select="true"]') || 'compare';

  if (kind === 'exists') {
    return {
      exists: readValue(nodeEl, '[data-logic-exists-value="true"]'),
    };
  }

  if (kind === 'not') {
    const childrenWrap = nodeEl.querySelector('.wf2-logic-tree-children');
    const childNodeEl = readDirectChildNodes(childrenWrap)[0] || null;
    return {
      not: childNodeEl ? readLogicConditionNode(childNodeEl) : {
        compare: {
          left: '${vars.value}',
          op: '==',
          right: '',
        },
      },
    };
  }

  if (kind === 'and' || kind === 'or') {
    const childrenWrap = nodeEl.querySelector('.wf2-logic-tree-children');
    return {
      [kind]: readDirectChildNodes(childrenWrap).map((child) => readLogicConditionNode(child)),
    };
  }

  return {
    compare: {
      left: readValue(nodeEl, '[data-logic-compare-left="true"]'),
      op: readValue(nodeEl, '[data-logic-compare-op="true"]') || '==',
      right: readValue(nodeEl, '[data-logic-compare-right="true"]'),
    },
  };
}

export function readLogicStepDraft(scope) {
  const cases = [...(scope?.querySelectorAll('[data-logic-case-row]') || [])].map((row) => {
    const whenWrap = row.querySelector('[data-logic-case-when="true"]');
    const rootNode = readDirectChildNodes(whenWrap)[0] || null;

    return {
      when: rootNode
        ? readLogicConditionNode(rootNode)
        : {
            compare: {
              left: '${vars.value}',
              op: '==',
              right: '',
            },
          },
      outcome: readValue(row, '[data-logic-case-outcome-input="true"]'),
    };
  });

  return {
    cases,
    defaultOutcome: readValue(scope, '[data-logic-default-input="true"]'),
  };
}
