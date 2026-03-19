import { LineCounter, parseDocument } from 'yaml';

const END_TARGETS = new Set(['$end', '$reject']);

function uniqStrings(values) {
  const out = [];
  const seen = new Set();

  for (const value of values || []) {
    if (typeof value !== 'string') {
      continue;
    }

    const safe = value.trim();
    if (!safe || seen.has(safe)) {
      continue;
    }

    seen.add(safe);
    out.push(safe);
  }

  return out;
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
    ]);
  }

  return [];
}

function buildYamlIssue(level, message, location = {}) {
  return {
    level,
    message,
    offset:
      typeof location.offset === 'number' && Number.isFinite(location.offset)
        ? location.offset
        : null,
    line:
      typeof location.line === 'number' && Number.isFinite(location.line)
        ? location.line
        : null,
    column:
      typeof location.column === 'number' && Number.isFinite(location.column)
        ? location.column
        : null,
  };
}

function getErrorLocation(err, lineCounter) {
  let offset = null;
  let line = null;
  let column = null;

  if (err?.linePos?.start) {
    line = err.linePos.start.line ?? null;
    column = err.linePos.start.col ?? null;
  }

  if (Array.isArray(err?.pos) && typeof err.pos[0] === 'number') {
    offset = err.pos[0];
  } else if (typeof err?.pos === 'number') {
    offset = err.pos;
  }

  if ((line === null || column === null) && offset !== null && lineCounter) {
    try {
      const pos = lineCounter.linePos(offset);
      line = pos.line ?? line;
      column = pos.col ?? column;
    } catch {
      // ignore
    }
  }

  return { offset, line, column };
}

function extractSyntaxIssues(doc, lineCounter) {
  const issues = [];

  for (const err of doc.errors || []) {
    issues.push(
      buildYamlIssue(
        'error',
        String(err),
        getErrorLocation(err, lineCounter),
      ),
    );
  }

  for (const warning of doc.warnings || []) {
    issues.push(
      buildYamlIssue(
        'warning',
        String(warning),
        getErrorLocation(warning, lineCounter),
      ),
    );
  }

  return issues;
}

function safeToJs(doc) {
  try {
    return doc.toJS() || {};
  } catch {
    return {};
  }
}

function buildDraftNodes(stepsObj) {
  if (!stepsObj || typeof stepsObj !== 'object' || Array.isArray(stepsObj)) {
    return [];
  }

  return Object.entries(stepsObj).map(([stepId, stepObj]) => {
    const outcomes = extractStepOutcomes(stepObj);

    return {
      id: stepId,
      type:
        stepObj && typeof stepObj === 'object' && typeof stepObj.type === 'string'
          ? stepObj.type
          : 'unknown',
      title:
        stepObj && typeof stepObj === 'object' && typeof stepObj.title === 'string'
          ? stepObj.title
          : stepId,
      produces_outcome: outcomes.length > 0,
      outcomes,
      is_terminal: false,
    };
  });
}

function buildDraftEdges(flowArray) {
  const issues = [];
  const edges = [];

  if (!Array.isArray(flowArray)) {
    return { edges, issues };
  }

  flowArray.forEach((item, index) => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      issues.push(
        buildYamlIssue(
          'warning',
          `workflow.flow[${index}] is not a valid mapping.`,
        ),
      );
      return;
    }

    const from = typeof item.from === 'string' ? item.from.trim() : '';
    const to = typeof item.to === 'string' ? item.to.trim() : '';
    const on = typeof item.on === 'string' ? item.on.trim() : '';

    if (!from || !to) {
      issues.push(
        buildYamlIssue(
          'warning',
          `workflow.flow[${index}] is missing a valid "from" or "to" value.`,
        ),
      );
      return;
    }

    edges.push(
      on
        ? { from, on, to }
        : { from, to },
    );
  });

  return { edges, issues };
}

function computeReachableNodeIds(startId, edges, nodeIds) {
  if (!startId || !nodeIds.has(startId)) {
    return new Set();
  }

  const adjacency = new Map();
  for (const nodeId of nodeIds) {
    adjacency.set(nodeId, []);
  }

  for (const edge of edges || []) {
    if (!nodeIds.has(edge.from)) {
      continue;
    }

    if (nodeIds.has(edge.to)) {
      adjacency.get(edge.from).push(edge.to);
    }
  }

  const visited = new Set([startId]);
  const queue = [startId];

  while (queue.length) {
    const current = queue.shift();
    for (const next of adjacency.get(current) || []) {
      if (!visited.has(next)) {
        visited.add(next);
        queue.push(next);
      }
    }
  }

  return visited;
}

function extractDraftIssues(rootObj, graph, flowIssues) {
  const issues = [...flowIssues];
  const workflow =
    rootObj?.workflow && typeof rootObj.workflow === 'object'
      ? rootObj.workflow
      : null;

  if (rootObj?.schema !== undefined && rootObj.schema !== 'trustpoint.workflow.v2') {
    issues.push(
      buildYamlIssue(
        'warning',
        'schema should be "trustpoint.workflow.v2".',
      ),
    );
  }

  if (!rootObj?.name || typeof rootObj.name !== 'string' || !rootObj.name.trim()) {
    issues.push(
      buildYamlIssue(
        'warning',
        'name is missing or empty.',
      ),
    );
  }

  if (!rootObj?.trigger || typeof rootObj.trigger !== 'object') {
    issues.push(
      buildYamlIssue(
        'warning',
        'trigger block is missing.',
      ),
    );
  } else if (!rootObj.trigger.on || typeof rootObj.trigger.on !== 'string') {
    issues.push(
      buildYamlIssue(
        'warning',
        'trigger.on is missing.',
      ),
    );
  }

  if (!workflow) {
    issues.push(
      buildYamlIssue(
        'error',
        'workflow block is missing.',
      ),
    );
    return issues;
  }

  if (!workflow.steps || typeof workflow.steps !== 'object' || Array.isArray(workflow.steps)) {
    issues.push(
      buildYamlIssue(
        'error',
        'workflow.steps must be a mapping.',
      ),
    );
  }

  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  const nodeIds = new Set(nodes.map((node) => node.id));
  const startId = typeof graph.start === 'string' ? graph.start : null;

  if (!nodes.length) {
    issues.push(
      buildYamlIssue(
        'warning',
        'No workflow steps are defined yet.',
      ),
    );
  }

  if (!Array.isArray(workflow.flow)) {
    issues.push(
      buildYamlIssue(
        'warning',
        'workflow.flow should be a list.',
      ),
    );
  } else if (!edges.length) {
    issues.push(
      buildYamlIssue(
        'info',
        'No flow edges are defined yet.',
      ),
    );
  }

  if (!startId) {
    issues.push(
      buildYamlIssue(
        'error',
        'workflow.start is missing.',
      ),
    );
  } else if (!nodeIds.has(startId)) {
    issues.push(
      buildYamlIssue(
        'error',
        `workflow.start references unknown step "${startId}".`,
      ),
    );
  }

  for (const edge of edges) {
    if (!nodeIds.has(edge.from)) {
      issues.push(
        buildYamlIssue(
          'error',
          `Flow source "${edge.from}" does not exist in workflow.steps.`,
        ),
      );
    }

    if (!nodeIds.has(edge.to) && !END_TARGETS.has(edge.to)) {
      issues.push(
        buildYamlIssue(
          'error',
          `Flow target "${edge.to}" does not exist in workflow.steps.`,
        ),
      );
    }
  }

  for (const node of nodes) {
    const outgoing = edges.filter((edge) => edge.from === node.id);
    const outcomeEdges = outgoing.filter((edge) => typeof edge.on === 'string' && edge.on.trim());
    const linearEdges = outgoing.filter((edge) => !edge.on);

    if (node.produces_outcome) {
      const mappedOutcomes = new Set(outcomeEdges.map((edge) => edge.on));
      const missingOutcomes = (node.outcomes || []).filter((outcome) => !mappedOutcomes.has(outcome));

      if (linearEdges.length) {
        issues.push(
          buildYamlIssue(
            'error',
            `Step "${node.id}" produces outcomes but also has a linear edge.`,
          ),
        );
      }

      if (missingOutcomes.length) {
        issues.push(
          buildYamlIssue(
            'warning',
            `Step "${node.id}" is missing flow mappings for outcomes: ${missingOutcomes.join(', ')}.`,
          ),
        );
      }
    } else if (outcomeEdges.length) {
      issues.push(
        buildYamlIssue(
          'error',
          `Step "${node.id}" does not produce outcomes but has outcome-based flow edges.`,
        ),
      );
    }

    if (!node.produces_outcome && linearEdges.length > 1) {
      issues.push(
        buildYamlIssue(
          'error',
          `Step "${node.id}" has multiple linear flow edges.`,
        ),
      );
    }
  }

  const reachable = computeReachableNodeIds(startId, edges, nodeIds);
  if (startId && nodeIds.has(startId)) {
    for (const node of nodes) {
      if (!reachable.has(node.id)) {
        issues.push(
          buildYamlIssue(
            'info',
            `Step "${node.id}" is not reachable from workflow.start.`,
          ),
        );
      }
    }
  }

  return issues;
}

function buildDraftGraph(rootObj) {
  const workflow =
    rootObj?.workflow && typeof rootObj.workflow === 'object'
      ? rootObj.workflow
      : {};

  const stepsObj =
    workflow?.steps && typeof workflow.steps === 'object' && !Array.isArray(workflow.steps)
      ? workflow.steps
      : {};

  const nodes = buildDraftNodes(stepsObj);
  const { edges, issues: flowIssues } = buildDraftEdges(workflow?.flow);

  return {
    graph: {
      ir_version: 'draft',
      name: typeof rootObj?.name === 'string' ? rootObj.name : null,
      enabled: Boolean(rootObj?.enabled ?? true),
      start: typeof workflow?.start === 'string' ? workflow.start : null,
      nodes,
      edges,
    },
    flowIssues,
  };
}

export function parseDraftWorkflowGraph(yamlText) {
  const lineCounter = new LineCounter();
  const doc = parseDocument(yamlText, {
    prettyErrors: true,
    keepSourceTokens: true,
    lineCounter,
  });

  const syntaxIssues = extractSyntaxIssues(doc, lineCounter);
  const rootObj = safeToJs(doc);
  const { graph, flowIssues } = buildDraftGraph(rootObj);
  const semanticIssues = extractDraftIssues(rootObj, graph, flowIssues);

  return {
    graph,
    issues: [...syntaxIssues, ...semanticIssues],
    hasSyntaxErrors: syntaxIssues.some((item) => item.level === 'error'),
  };
}