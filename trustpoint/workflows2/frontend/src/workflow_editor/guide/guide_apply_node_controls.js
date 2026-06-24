import { escapeHtml } from '../shared/dom.js';
import {
  encodePath,
  getOperatorOptions,
  renderButton,
  renderDangerButton,
} from './guide_apply_shared.js';

export function renderNodeOperatorRow({
  catalog,
  currentOperator,
  ruleIndex,
  path,
  isRoot,
  allowRemove,
}) {
  const encodedPath = encodePath(path);
  const options = getOperatorOptions(catalog);

  return `
    <div class="wf2-cond-header-row">
      <div class="wf2-cond-header-main">
        <label class="form-label form-label-sm mb-1">Operator</label>
        <select class="form-select form-select-sm wf2-cond-operator-select" data-apply-node-operator-input="true">
          ${options
            .map((operatorName) => {
              const selected = operatorName === currentOperator ? ' selected' : '';
              return `<option value="${escapeHtml(operatorName)}"${selected}>${escapeHtml(operatorName)}</option>`;
            })
            .join('')}
        </select>
      </div>

      <div class="wf2-cond-header-actions">
        ${renderButton(
          'set-apply-node-operator',
          'Apply',
          ` data-apply-rule-index="${ruleIndex}" data-apply-node-path="${encodedPath}"`,
        )}

        ${
          allowRemove
            ? (
                isRoot
                  ? renderDangerButton(
                      'remove-apply-rule',
                      'Remove rule',
                      ` data-apply-rule-index="${ruleIndex}"`,
                    )
                  : renderDangerButton(
                      'remove-apply-child',
                      'Remove',
                      ` data-apply-rule-index="${ruleIndex}" data-apply-node-path="${encodedPath}"`,
                    )
              )
            : ''
        }
      </div>
    </div>
  `;
}

export function renderAddChildControls(ruleIndex, path) {
  const encodedPath = encodePath(path);

  return `
    <div class="wf2-inline-save-row" data-apply-child-controls="true">
      <div class="wf2-inline-save-input">
        <label class="form-label form-label-sm mb-1">Add nested condition</label>
        <select class="form-select form-select-sm" data-apply-child-operator-input="true">
          <option value="compare">compare</option>
          <option value="exists">exists</option>
          <option value="not">not</option>
          <option value="and">and</option>
          <option value="or">or</option>
        </select>
      </div>

      <div class="wf2-inline-save-action">
        <label class="form-label form-label-sm mb-1 d-block">&nbsp;</label>
        ${renderButton(
          'add-apply-child',
          'Add',
          ` data-apply-rule-index="${ruleIndex}" data-apply-node-path="${encodedPath}"`,
        )}
      </div>
    </div>
  `;
}
