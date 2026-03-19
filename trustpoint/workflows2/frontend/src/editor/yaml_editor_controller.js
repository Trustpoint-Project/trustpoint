import { indentWithTab, redo, undo } from '@codemirror/commands';
import { EditorState } from '@codemirror/state';
import { EditorView, keymap } from '@codemirror/view';
import { yaml as yamlLanguage } from '@codemirror/lang-yaml';
import { basicSetup } from 'codemirror';

function buildEditorTheme() {
  return EditorView.theme({
    '&': {
      height: '68vh',
      border: '1px solid #dee2e6',
      borderRadius: '0.5rem',
      backgroundColor: '#fff',
      fontSize: '0.95rem',
    },
    '.cm-scroller': {
      fontFamily:
        'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
      lineHeight: '1.5',
    },
    '.cm-content': {
      padding: '0.75rem 0',
    },
    '.cm-gutters': {
      backgroundColor: '#fafafa',
      borderRight: '1px solid #e9ecef',
    },
    '.cm-activeLineGutter': {
      backgroundColor: '#f1f3f5',
    },
    '.cm-activeLine': {
      backgroundColor: '#fcfcfd',
    },
    '.cm-focused': {
      outline: 'none',
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