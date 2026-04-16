# workflows2/tests/test_eval.py
from __future__ import annotations

from django.test import SimpleTestCase

from workflows2.engine.context import RuntimeContext
from workflows2.engine.eval import eval_condition


class EvalConditionTests(SimpleTestCase):
    def test_compare_allows_numeric_string_rhs_against_number(self) -> None:
        ctx = RuntimeContext(event={}, vars={'http_status': 200})

        cond = {
            'kind': 'compare',
            'left': {'kind': 'ref', 'path': ['vars', 'http_status']},
            'op': '==',
            'right': '200',
        }

        self.assertTrue(eval_condition(cond, ctx))

    def test_compare_allows_numeric_string_lhs_against_number(self) -> None:
        ctx = RuntimeContext(event={}, vars={'score': '10'})

        cond = {
            'kind': 'compare',
            'left': {'kind': 'ref', 'path': ['vars', 'score']},
            'op': '>',
            'right': 2,
        }

        self.assertTrue(eval_condition(cond, ctx))
