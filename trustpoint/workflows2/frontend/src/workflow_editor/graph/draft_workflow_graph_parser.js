import { parseDocument } from 'yaml';
import { analyzeWorkflowVariableAvailability } from '../document/variable_availability.js';

export const TRIGGER_NODE_ID = '__trigger__';
export const APPLY_NODE_ID = '__apply__';

function deepClone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function uniqStrings(values) {
  const out = [];
  const seen = new Set();

  for (const value of values || []) {
    if (typeof value !== 'string') {
      continue;
    }
    const s = value.trim();
    if (!s || seen.has(s)) {
      continue;
    }
    seen.add(s);
    out.push(s);
  }

  return out;
}

function yamlErrorOffset(error) {
  if (Array.isArray(error?.pos) && typeof error.pos[0] === 'number') {
    return error.pos[0];
  }
  return null;
}

function pushIssue(issues, level, message, offset = null) {
  issues.push({
    level,
    message,
    offset: typeof offset === 'number' ? offset : null,
  });
}

function normalizeFlowEdge(item) {
  if (!item || typeof item !== 'object' || Array.isArray(item)) {
    return null;
  }

  const from = typeof item.from === 'string' ? item.from.trim() : '';
  const to = typeof item.to === 'string' ? item.to.trim() : '';
  const on = typeof item.on === 'string' ? item.on.trim() : '';

  if (!from || !to) {
    return null;
  }

  return {
    from,
    to,
    on: on || null,
  };
}

function buildTriggerApplyEdge() {
  return {
    from: TRIGGER_NODE_ID,
    to: APPLY_NODE_ID,
    on: null,
    label: 'apply',
    is_helper_edge: true,
  };
}

function buildApplyStartEdge(start) {
  return {
    from: APPLY_NODE_ID,
    to: start,
    on: null,
    label: 'start',
    is_start_edge: true,
    is_helper_edge: true,
  };
}

function extractStepOutcomes(stepObj) {
  if (!stepObj || typeof stepObj !== 'object') {
    return [];
  }

  if (stepObj.type === 'logic') {
    const cases = Array.isArray(stepObj.cases) ? stepObj.cases : [];
    const caseOutcomes = cases
      .map((item) => (item && typeof item === 'object' ? item.outcome : null))
      .filter((value) => typeof value === 'string');

    const defaultOutcome = typeof stepObj.default === 'string' ? [stepObj.default] : [];
    return uniqStrings([...caseOutcomes, ...defaultOutcome]);
  }

  if (stepObj.type === 'approval') {
    return uniqStrings([
      stepObj.approved_outcome,
      stepObj.rejected_outcome,
      stepObj.timeout_outcome,
    ]);
  }

  return [];
}

function buildNodes(stepsObj, edges) {
  const hasOutgoing = new Set(edges.map((edge) => edge.from));

  return Object.entries(stepsObj).map(([stepId, stepObj]) => {
    const type = typeof stepObj?.type === 'string' ? stepObj.type : 'unknown';
    const title =
      typeof stepObj?.title === 'string' && stepObj.title.trim()
        ? stepObj.title.trim()
        : stepId;

    const outcomes = extractStepOutcomes(stepObj);
    const producesOutcome = outcomes.length > 0;

    return {
      id: stepId,
      type,
      title,
      produces_outcome: producesOutcome,
      outcomes,
      is_terminal: !hasOutgoing.has(stepId),
      is_unreachable: false,
      is_virtual: false,
      step_data: deepClone(stepObj),
    };
  });
}

function normalizeTriggerSources(rootObj) {
  const sources =
    rootObj?.trigger?.sources && typeof rootObj.trigger.sources === 'object' && !Array.isArray(rootObj.trigger.sources)
      ? rootObj.trigger.sources
      : {};

  return {
    trustpoint: Boolean(sources.trustpoint),
    ca_ids: Array.isArray(sources.ca_ids) ? sources.ca_ids.filter((value) => Number.isInteger(value)) : [],
    domain_ids: Array.isArray(sources.domain_ids) ? sources.domain_ids.filter((value) => Number.isInteger(value)) : [],
    device_ids: Array.isArray(sources.device_ids)
      ? sources.device_ids.filter((value) => typeof value === 'string' && value.trim()).map((value) => value.trim())
      : [],
  };
}

function buildTriggerNode(rootObj) {
  const triggerKey = typeof rootObj?.trigger?.on === 'string' ? rootObj.trigger.on.trim() : '';
  const sources = normalizeTriggerSources(rootObj);
  const explicitCount = sources.ca_ids.length + sources.domain_ids.length + sources.device_ids.length;
  const scopeSummary = sources.trustpoint
    ? 'All sources'
    : `${explicitCount} scoped source${explicitCount === 1 ? '' : 's'}`;

  return {
    id: TRIGGER_NODE_ID,
    type: 'trigger',
    title: triggerKey || 'Trigger',
    produces_outcome: false,
    outcomes: [],
    is_terminal: false,
    is_unreachable: false,
    is_virtual: true,
    is_trigger: true,
    trigger_key: triggerKey || null,
    trigger_sources: sources,
    scope_summary: scopeSummary,
  };
}

function buildApplyNode(rootObj) {
  const rules = Array.isArray(rootObj?.apply) ? rootObj.apply : [];
  const ruleCount = rules.length;

  return {
    id: APPLY_NODE_ID,
    type: 'apply',
    title: 'Apply rules',
    produces_outcome: false,
    outcomes: [],
    is_terminal: false,
    is_unreachable: false,
    is_virtual: true,
    is_apply: true,
    apply_rules: deepClone(rules),
    apply_count: ruleCount,
    scope_summary: ruleCount
      ? `${ruleCount} precondition${ruleCount === 1 ? '' : 's'}`
      : 'No preconditions',
  };
}

function warnOnMissingOutcomeMappings(issues, stepsObj, edges) {
  const mappedOutcomesByStep = new Map();

  for (const edge of edges) {
    if (!edge?.on) {
      continue;
    }

    if (!mappedOutcomesByStep.has(edge.from)) {
      mappedOutcomesByStep.set(edge.from, new Set());
    }
    mappedOutcomesByStep.get(edge.from).add(edge.on);
  }

  for (const [stepId, stepObj] of Object.entries(stepsObj)) {
    const outcomes = extractStepOutcomes(stepObj);
    if (!outcomes.length) {
      continue;
    }

    const mapped = mappedOutcomesByStep.get(stepId) || new Set();
    const missing = outcomes.filter((outcome) => !mapped.has(outcome));
    if (!missing.length) {
      continue;
    }

    pushIssue(
      issues,
      'warning',
      `Step "${stepId}" has unlinked outcomes: ${missing.join(', ')}`,
    );
  }
}

function collectReachableSteps(start, stepsObj, edges) {
  if (!start || !Object.prototype.hasOwnProperty.call(stepsObj, start)) {
    return new Set();
  }

  const outgoing = new Map();
  for (const edge of edges) {
    if (!outgoing.has(edge.from)) {
      outgoing.set(edge.from, []);
    }
    outgoing.get(edge.from).push(edge.to);
  }

  const reachable = new Set();
  const pending = [start];

  while (pending.length) {
    const stepId = pending.pop();
    if (reachable.has(stepId) || !Object.prototype.hasOwnProperty.call(stepsObj, stepId)) {
      continue;
    }

    reachable.add(stepId);
    for (const target of outgoing.get(stepId) || []) {
      if (Object.prototype.hasOwnProperty.call(stepsObj, target)) {
        pending.push(target);
      }
    }
  }

  return reachable;
}

export function parseDraftWorkflowGraph(yamlText) {
  const doc = parseDocument(yamlText, {
    prettyErrors: true,
    keepSourceTokens: true,
  });

  if (doc.errors.length) {
    const err = doc.errors[0];
    const e = new Error(String(err));
    e.offset = yamlErrorOffset(err);
    throw e;
  }

  const rootObj = doc.toJS() || {};
  const issues = [];
  const variableAvailability = analyzeWorkflowVariableAvailability(rootObj);

  const workflow =
    rootObj.workflow && typeof rootObj.workflow === 'object' && !Array.isArray(rootObj.workflow)
      ? rootObj.workflow
      : null;

  if (!workflow) {
    pushIssue(issues, 'warning', 'Missing workflow block.');
    return {
      graph: {
        name: typeof rootObj.name === 'string' ? rootObj.name : 'Workflow',
        enabled: rootObj.enabled !== false,
        trigger_key: typeof rootObj?.trigger?.on === 'string' ? rootObj.trigger.on : null,
        trigger_sources: normalizeTriggerSources(rootObj),
        trigger_node_id: TRIGGER_NODE_ID,
        apply_node_id: APPLY_NODE_ID,
        start: null,
        nodes: [buildTriggerNode(rootObj), buildApplyNode(rootObj)],
        edges: [buildTriggerApplyEdge()],
        raw_steps: {},
        raw_flow: [],
      },
      issues,
    };
  }

  const stepsObj =
    workflow.steps && typeof workflow.steps === 'object' && !Array.isArray(workflow.steps)
      ? workflow.steps
      : {};

  const flowList = Array.isArray(workflow.flow) ? workflow.flow : [];

  if (workflow.steps !== undefined && (Array.isArray(workflow.steps) || workflow.steps === null || typeof workflow.steps !== 'object')) {
    pushIssue(issues, 'warning', '"workflow.steps" should be a mapping.');
  }

  if (workflow.flow !== undefined && !Array.isArray(workflow.flow)) {
    pushIssue(issues, 'warning', '"workflow.flow" should be a list.');
  }

  const start =
    typeof workflow.start === 'string' && workflow.start.trim()
      ? workflow.start.trim()
      : null;

  if (start && !Object.prototype.hasOwnProperty.call(stepsObj, start)) {
    pushIssue(issues, 'warning', `workflow.start "${start}" does not reference an existing step.`);
  }

  const edges = [];
  const seenEdges = new Set();

  for (const item of flowList) {
    const edge = normalizeFlowEdge(item);
    if (!edge) {
      pushIssue(issues, 'warning', 'Ignoring invalid flow item.');
      continue;
    }

    if (!Object.prototype.hasOwnProperty.call(stepsObj, edge.from)) {
      pushIssue(issues, 'warning', `Flow source "${edge.from}" does not exist.`);
    }

    if (!Object.prototype.hasOwnProperty.call(stepsObj, edge.to)) {
      pushIssue(issues, 'warning', `Flow target "${edge.to}" does not exist.`);
    }

    const edgeKey = `${edge.from}|${edge.on || ''}|${edge.to}`;
    if (seenEdges.has(edgeKey)) {
      continue;
    }
    seenEdges.add(edgeKey);

    edges.push(edge);
  }

  warnOnMissingOutcomeMappings(issues, stepsObj, edges);

  const nodes = buildNodes(stepsObj, edges);
  const hasValidStart = !!(start && Object.prototype.hasOwnProperty.call(stepsObj, start));
  const reachable = hasValidStart ? collectReachableSteps(start, stepsObj, edges) : new Set();
  const unreachable = hasValidStart
    ? Object.keys(stepsObj).filter((stepId) => !reachable.has(stepId))
    : [];

  if (hasValidStart && unreachable.length) {
    pushIssue(
      issues,
      'warning',
      `Unreachable steps from workflow.start "${start}": ${unreachable.join(', ')}`,
    );
  }

  for (const node of nodes) {
    node.is_unreachable = unreachable.includes(node.id);
    const stepAvailability = variableAvailability.stepAvailability?.[node.id];
    node.available_var_names = stepAvailability?.availableVarNames || [];
    node.produced_var_names = stepAvailability?.producedVarNames || [];
  }
  const helperEdges = hasValidStart
    ? [buildTriggerApplyEdge(), buildApplyStartEdge(start)]
    : [buildTriggerApplyEdge()];
  const graphEdges = [...helperEdges, ...edges];

  return {
    graph: {
      name: typeof rootObj.name === 'string' ? rootObj.name : 'Workflow',
      enabled: rootObj.enabled !== false,
      trigger_key: typeof rootObj?.trigger?.on === 'string' ? rootObj.trigger.on : null,
      trigger_sources: normalizeTriggerSources(rootObj),
      trigger_node_id: TRIGGER_NODE_ID,
      apply_node_id: APPLY_NODE_ID,
      start,
      nodes: [buildTriggerNode(rootObj), buildApplyNode(rootObj), ...nodes],
      edges: graphEdges,
      raw_steps: deepClone(stepsObj),
      raw_flow: deepClone(flowList),
    },
    issues,
  };
}
