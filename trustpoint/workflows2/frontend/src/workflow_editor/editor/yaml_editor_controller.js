import { indentWithTab, redo, undo } from '@codemirror/commands';
import { EditorState } from '@codemirror/state';
import {
  defaultHighlightStyle,
  HighlightStyle,
  syntaxHighlighting,
} from '@codemirror/language';
import { yaml as yamlLanguage } from '@codemirror/lang-yaml';
import { tags } from '@lezer/highlight';
import { EditorView, keymap } from '@codemirror/view';
import { basicSetup } from 'codemirror';

function buildEditorHighlightStyle() {
  return HighlightStyle.define([
    {
      tag: [tags.propertyName, tags.attributeName, tags.labelName],
      color: 'var(--wf2-editor-key)',
      fontWeight: '600',
    },
    {
      tag: [tags.string],
      color: 'var(--wf2-editor-string)',
    },
    {
      tag: [tags.number],
      color: 'var(--wf2-editor-number)',
    },
    {
      tag: [tags.bool, tags.null, tags.atom, tags.keyword],
      color: 'var(--wf2-editor-atom)',
      fontWeight: '600',
    },
    {
      tag: [tags.comment],
      color: 'var(--wf2-editor-comment)',
      fontStyle: 'italic',
    },
    {
      tag: [tags.operator, tags.separator, tags.punctuation, tags.bracket],
      color: 'var(--wf2-editor-punctuation)',
    },
    {
      tag: [tags.invalid],
      color: 'var(--wf2-editor-invalid)',
      textDecoration: 'underline wavy var(--wf2-editor-invalid)',
    },
  ]);
}

function buildEditorTheme() {
  return EditorView.theme({
    '&': {
      height: '68vh',
      border: '1px solid var(--wf2-editor-border)',
      borderRadius: '0.5rem',
      backgroundColor: 'var(--wf2-editor-surface)',
      color: 'var(--wf2-editor-text)',
      fontSize: '0.95rem',
    },
    '.cm-scroller': {
      fontFamily:
        'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
      lineHeight: '1.5',
      color: 'var(--wf2-editor-text)',
    },
    '.cm-content': {
      padding: '0.75rem 0',
      caretColor: 'var(--wf2-editor-accent)',
    },
    '.cm-line': {
      padding: '0 0.85rem',
    },
    '.cm-gutters': {
      backgroundColor: 'var(--wf2-editor-gutter)',
      borderRight: '1px solid var(--wf2-editor-border-soft)',
      color: 'var(--wf2-editor-muted)',
    },
    '.cm-gutterElement': {
      padding: '0 0.55rem 0 0.75rem',
    },
    '.cm-activeLineGutter': {
      backgroundColor: 'var(--wf2-editor-active-gutter)',
    },
    '.cm-activeLine': {
      backgroundColor: 'transparent',
      boxShadow: 'inset 3px 0 0 var(--wf2-editor-active-line)',
    },
    '.cm-focused': {
      outline: 'none',
    },
    '.cm-cursor, .cm-dropCursor': {
      borderLeftColor: 'var(--wf2-editor-accent)',
    },
    '.cm-matchingBracket': {
      backgroundColor: 'var(--wf2-editor-selection)',
      outline: '1px solid var(--wf2-editor-border-soft)',
      color: 'var(--wf2-editor-text)',
    },
    '.cm-nonmatchingBracket': {
      outline: '1px solid var(--wf2-editor-invalid)',
      color: 'var(--wf2-editor-invalid)',
    },
    '.cm-panels, .cm-tooltip, .cm-completionInfo': {
      backgroundColor: 'var(--wf2-editor-surface)',
      color: 'var(--wf2-editor-text)',
      border: '1px solid var(--wf2-editor-border)',
    },
  });
}

function getCursorInfoFromView(view) {
  const pos = view.state.selection.main.head;
  const line = view.state.doc.lineAt(pos);

  return {
    line: line.number,
    col: pos - line.from + 1,
    offset: pos,
  };
}

function restoreScrollAndFocus(view, hadFocus, prevScrollTop, prevScrollLeft) {
  requestAnimationFrame(() => {
    const scroller = view.scrollDOM;
    scroller.scrollTop = prevScrollTop;
    scroller.scrollLeft = prevScrollLeft;

    if (hadFocus) {
      view.focus();
    }
  });
}

export function createWorkflowEditor({
  mount,
  initialDoc,
  onDocumentChange,
  onCursorChange,
}) {
  const view = new EditorView({
    state: EditorState.create({
      doc: initialDoc,
      extensions: [
        basicSetup,
        yamlLanguage(),
        syntaxHighlighting(defaultHighlightStyle, { fallback: true }),
        syntaxHighlighting(buildEditorHighlightStyle()),
        keymap.of([indentWithTab]),
        buildEditorTheme(),
        EditorView.updateListener.of((update) => {
          if (update.docChanged) {
            onDocumentChange?.(update.state.doc.toString());
          }

          if (update.docChanged || update.selectionSet) {
            onCursorChange?.(getCursorInfoFromView(update.view));
          }
        }),
      ],
    }),
    parent: mount,
  });

  return {
    view,

    getValue() {
      return view.state.doc.toString();
    },

    getCursorInfo() {
      return getCursorInfoFromView(view);
    },

    focusOffset(offset) {
      const safeOffset = Math.max(0, Math.min(Number(offset) || 0, view.state.doc.length));
      view.focus();
      view.dispatch({
        selection: {
          anchor: safeOffset,
          head: safeOffset,
        },
        scrollIntoView: true,
      });
    },

    undo() {
      return undo(view);
    },

    redo() {
      return redo(view);
    },

    replaceValue(newValue, options = {}) {
      const oldDoc = view.state.doc.toString();
      if (newValue === oldDoc) {
        return;
      }

      const {
        preserveScroll = true,
        searchText = null,
        searchOffset = 0,
      } = options;

      const currentHead = view.state.selection.main.head;

      let nextHead = Math.min(currentHead, newValue.length);
      if (searchText) {
        const idx = newValue.indexOf(searchText);
        if (idx >= 0) {
          nextHead = Math.min(idx + searchOffset, newValue.length);
        }
      }

      const scroller = view.scrollDOM;
      const prevScrollTop = scroller.scrollTop;
      const prevScrollLeft = scroller.scrollLeft;
      const hadFocus = view.hasFocus;

      view.dispatch({
        changes: {
          from: 0,
          to: oldDoc.length,
          insert: newValue,
        },
        selection: {
          anchor: nextHead,
          head: nextHead,
        },
      });

      if (preserveScroll) {
        restoreScrollAndFocus(view, hadFocus, prevScrollTop, prevScrollLeft);
        return;
      }

      requestAnimationFrame(() => {
        if (hadFocus) {
          view.focus();
        }
        view.dispatch({
          selection: {
            anchor: nextHead,
            head: nextHead,
          },
          scrollIntoView: true,
        });
      });
    },

    insertText(insertTextValue) {
      const selection = view.state.selection.main;
      const scroller = view.scrollDOM;
      const prevScrollTop = scroller.scrollTop;
      const prevScrollLeft = scroller.scrollLeft;
      const hadFocus = view.hasFocus;

      const insertLen = insertTextValue.length;
      const nextPos = selection.from + insertLen;

      view.dispatch({
        changes: {
          from: selection.from,
          to: selection.to,
          insert: insertTextValue,
        },
        selection: {
          anchor: nextPos,
          head: nextPos,
        },
      });

      restoreScrollAndFocus(view, hadFocus, prevScrollTop, prevScrollLeft);
    },
  };
}
