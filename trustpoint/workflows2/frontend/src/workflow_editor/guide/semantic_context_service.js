import { parseDocument } from 'yaml';
import { analyzeWorkflowVariableAvailability } from '../document/variable_availability.js';
import {
  areaTitle,
  extractKnownVarNames,
  extractStepSummaries,
  pathToString,
  resolveArea,
  uniqStrings,
} from './semantic_context_workflow_tools.js';
import {
  deriveTextPathAtOffset,
  findDeepestPath,
  getLineInfoAtOffset,
} from './semantic_context_path_tools.js';

export function parseYamlStatus(yamlText) {
  try {
    const doc = parseDocument(yamlText, {
      prettyErrors: true,
    });

    if (doc.errors.length) {
      return {
        ok: false,
        message: String(doc.errors[0]),
      };
    }

    if (doc.warnings.length) {
      return {
        ok: true,
        message: `Parsed with warning: ${String(doc.warnings[0])}`,
      };
    }

    return {
      ok: true,
      message: 'YAML parsed successfully.',
    };
  } catch (err) {
    return {
      ok: false,
      message: err instanceof Error ? err.message : String(err),
    };
  }
}

function buildInvalidContext(message) {
  return {
    ok: false,
    area: 'invalid',
    title: areaTitle('invalid'),
    path: [],
    pathLabel: '(invalid)',
    parseMessage: message,
    triggerKey: null,
    stepIds: [],
    stepSummaries: [],
    currentStartStep: null,
    stepId: null,
    stepType: null,
    fieldKey: null,
    stepFieldKeys: [],
    knownVarNames: [],
    availableVarNames: [],
    producedVarNames: [],
    isReachableStep: false,
    flowFieldKey: null,
    currentFlowItem: null,
    currentFlowOutcomeOptions: [],
  };
}

export function deriveSemanticContext(yamlText, offset) {
  try {
    const doc = parseDocument(yamlText, {
      prettyErrors: true,
      keepSourceTokens: true,
    });

    if (doc.errors.length) {
      return buildInvalidContext(String(doc.errors[0]));
    }

    const rootObj = doc.toJS() || {};
    const astPath = findDeepestPath(doc.contents, offset, []) || [];
    const textPath = deriveTextPathAtOffset(yamlText, offset);
    const lineInfo = getLineInfoAtOffset(yamlText, offset);

    let path = astPath;
    if (lineInfo.isBlank || lineInfo.isComment || textPath.length > astPath.length) {
      path = textPath;
    }

    const area = resolveArea(path);

    const triggerKey =
      typeof rootObj?.trigger?.on === 'string' ? rootObj.trigger.on : null;

    const stepsObj =
      rootObj?.workflow?.steps && typeof rootObj.workflow.steps === 'object'
        ? rootObj.workflow.steps
        : {};

    const stepIds = Object.keys(stepsObj);
    const stepSummaries = extractStepSummaries(rootObj);
    const variableAvailability = analyzeWorkflowVariableAvailability(rootObj);

    const currentStartStep =
      typeof rootObj?.workflow?.start === 'string'
        ? rootObj.workflow.start
        : null;

    const stepId =
      path[0] === 'workflow' && path[1] === 'steps' && typeof path[2] === 'string'
        ? path[2]
        : null;

    const stepObj =
      stepId && stepsObj[stepId] && typeof stepsObj[stepId] === 'object'
        ? stepsObj[stepId]
        : null;

    const stepType =
      stepObj && typeof stepObj.type === 'string'
        ? stepObj.type
        : null;

    const fieldKey =
      path[0] === 'workflow' &&
      path[1] === 'steps' &&
      typeof path[2] === 'string' &&
      typeof path[3] === 'string'
        ? path[3]
        : null;

    const stepFieldKeys =
      stepObj && typeof stepObj === 'object'
        ? Object.keys(stepObj)
        : [];

    const flowArray =
      Array.isArray(rootObj?.workflow?.flow) ? rootObj.workflow.flow : [];

    const flowItemIndex =
      path[0] === 'workflow' && path[1] === 'flow' && typeof path[2] === 'number'
        ? path[2]
        : null;

    const currentFlowItem =
      flowItemIndex !== null &&
      flowArray[flowItemIndex] &&
      typeof flowArray[flowItemIndex] === 'object'
        ? flowArray[flowItemIndex]
        : null;

    const flowFieldKey =
      path[0] === 'workflow' &&
      path[1] === 'flow' &&
      typeof path[3] === 'string'
        ? path[3]
        : null;

    const allKnownOutcomes = uniqStrings(
      stepSummaries.flatMap((item) => item.outcomes || []),
    );

    const currentFlowFrom =
      currentFlowItem && typeof currentFlowItem.from === 'string'
        ? currentFlowItem.from
        : null;

    const currentFlowOutcomeOptions =
      currentFlowFrom
        ? (
            stepSummaries.find((item) => item.id === currentFlowFrom)?.outcomes ||
            allKnownOutcomes
          )
        : allKnownOutcomes;

    const currentStepAvailability =
      stepId && variableAvailability?.stepAvailability
        ? variableAvailability.stepAvailability[stepId] || null
        : null;

    return {
      ok: true,
      area,
      title: areaTitle(area),
      path,
      pathLabel: pathToString(path),
      parseMessage: 'YAML parsed successfully.',
      triggerKey,
      stepIds,
      stepSummaries,
      currentStartStep,
      stepId,
      stepType,
      fieldKey,
      stepFieldKeys,
      knownVarNames: extractKnownVarNames(rootObj),
      availableVarNames: currentStepAvailability?.availableVarNames || [],
      producedVarNames: currentStepAvailability?.producedVarNames || [],
      isReachableStep: currentStepAvailability?.isReachable || false,
      flowFieldKey,
      currentFlowItem,
      currentFlowOutcomeOptions,
    };
  } catch (err) {
    return buildInvalidContext(err instanceof Error ? err.message : String(err));
  }
}
