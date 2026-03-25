"""Parse and validate Workflow 2 expressions."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .errors import CompileError

# ----------------------------- AST nodes ----------------------------- #


@dataclass(frozen=True)
class RefExpr:
    """Reference expression such as `event.device.id`."""

    path: list[str]  # e.g. ["event","device","common_name"]


@dataclass(frozen=True)
class CallExpr:
    """Function-call expression such as `lower(vars.name)`."""

    name: str
    args: list[Any]  # args are AST nodes or literals


# ----------------------------- tokenization ----------------------------- #


@dataclass(frozen=True)
class Token:
    """One token produced by the expression tokenizer."""

    typ: str
    val: str
    pos: int


_MISSING = object()


def _is_number_start(s: str, i: int) -> bool:
    return s[i].isdigit() or (s[i] == '-' and i + 1 < len(s) and s[i + 1].isdigit())


def _scan_punctuation_token(s: str, i: int) -> tuple[Token, int]:
    ch = s[i]
    return Token(typ=ch, val=ch, pos=i), i + 1


def _scan_string_token(s: str, start: int) -> tuple[Token, int]:
    quote = s[start]
    i = start + 1
    n = len(s)
    buf: list[str] = []

    while i < n:
        ch = s[i]
        if ch == '\\':
            if i + 1 >= n:
                msg = 'Unterminated escape sequence in string literal'
                raise CompileError(msg)
            buf.append(s[i + 1])
            i += 2
            continue
        if ch == quote:
            return Token(typ='STRING', val=''.join(buf), pos=start), i + 1
        buf.append(ch)
        i += 1

    msg = 'Unterminated string literal'
    raise CompileError(msg)


def _scan_number_token(s: str, start: int) -> tuple[Token, int]:
    i = start + 1
    n = len(s)
    has_dot = False

    while i < n:
        ch = s[i]
        if ch.isdigit():
            i += 1
            continue
        if ch == '.' and not has_dot:
            has_dot = True
            i += 1
            continue
        break

    return Token(typ='NUMBER', val=s[start:i], pos=start), i


def _scan_ident_token(s: str, start: int) -> tuple[Token, int]:
    i = start + 1
    n = len(s)

    while i < n and (s[i].isalnum() or s[i] == '_'):
        i += 1

    return Token(typ='IDENT', val=s[start:i], pos=start), i


def _tokenize(s: str) -> list[Token]:
    tokens: list[Token] = []
    i = 0
    n = len(s)

    while i < n:
        ch = s[i]

        if ch.isspace():
            i += 1
            continue

        if ch in '(),.':
            token, i = _scan_punctuation_token(s, i)
            tokens.append(token)
            continue

        if ch in {"'", '"'}:
            token, i = _scan_string_token(s, i)
            tokens.append(token)
            continue

        if _is_number_start(s, i):
            token, i = _scan_number_token(s, i)
            tokens.append(token)
            continue

        if ch.isalpha() or ch == '_':
            token, i = _scan_ident_token(s, i)
            tokens.append(token)
            continue

        if ch == '$':
            msg = (
                "Unexpected '$' in expression. Expressions already live inside ${...}; "
                'reference values as vars.name or event.path inside that wrapper instead of nesting ${...}.'
            )
            raise CompileError(msg)

        msg = f"Unexpected character '{ch}' in expression"
        raise CompileError(msg)

    tokens.append(Token(typ='EOF', val='', pos=n))
    return tokens


# ----------------------------- parser ----------------------------- #


class _Parser:
    def __init__(self, tokens: list[Token], *, path: str) -> None:
        self.tokens = tokens
        self.i = 0
        self.path = path

    def cur(self) -> Token:
        return self.tokens[self.i]

    def eat(self, typ: str) -> Token:
        t = self.cur()
        if t.typ != typ:
            msg = f'Expected {typ} but found {t.typ}'
            raise CompileError(msg, path=self.path)
        self.i += 1
        return t

    def maybe(self, typ: str) -> Token | None:
        if self.cur().typ == typ:
            return self.eat(typ)
        return None

    def parse(self) -> Any:
        expr = self.parse_primary()
        if self.cur().typ != 'EOF':
            msg = 'Unexpected trailing tokens in expression'
            raise CompileError(msg, path=self.path)
        return expr

    def _ident_literal_value(self, ident: str) -> Any:
        low = ident.lower()
        if low == 'true':
            return True
        if low == 'false':
            return False
        if low == 'null':
            return None
        return _MISSING

    def _parse_call_expr(self, ident: str) -> CallExpr:
        self.eat('(')
        args: list[Any] = []

        if self.cur().typ != ')':
            while True:
                args.append(self.parse_primary())
                if self.maybe(','):
                    continue
                break

        self.eat(')')
        return CallExpr(name=ident, args=args)

    def _parse_ref_expr(self, ident: str) -> RefExpr:
        path = [ident]
        while self.maybe('.'):
            path.append(self.eat('IDENT').val)
        return RefExpr(path=path)

    def _parse_ident_primary(self) -> Any:
        ident = self.eat('IDENT').val
        literal = self._ident_literal_value(ident)
        if literal is not _MISSING:
            return literal

        if self.cur().typ == '(':
            return self._parse_call_expr(ident)

        return self._parse_ref_expr(ident)

    def _parse_number_primary(self) -> int | float:
        raw = self.eat('NUMBER').val
        try:
            if '.' in raw:
                return float(raw)
            return int(raw)
        except ValueError as e:
            msg = 'Invalid number literal'
            raise CompileError(msg, path=self.path) from e

    def _parse_string_primary(self) -> str:
        return self.eat('STRING').val

    def parse_primary(self) -> Any:
        current_type = self.cur().typ

        if current_type == 'IDENT':
            return self._parse_ident_primary()
        if current_type == 'NUMBER':
            return self._parse_number_primary()
        if current_type == 'STRING':
            return self._parse_string_primary()

        msg = f'Invalid expression token: {current_type}'
        raise CompileError(msg, path=self.path)


# ----------------------------- allowlist + public API ----------------------------- #

ALLOWED_REF_ROOTS: tuple[str, ...] = ('event', 'vars')

EXPRESSION_FUNCTION_GROUPS: tuple[dict[str, Any], ...] = (
    {
        'group': 'numeric',
        'functions': (
            {'name': 'add', 'title': 'add', 'description': 'Adds all arguments.'},
            {'name': 'sub', 'title': 'sub', 'description': 'Subtracts subsequent arguments from the first.'},
            {'name': 'mul', 'title': 'mul', 'description': 'Multiplies all arguments.'},
            {'name': 'div', 'title': 'div', 'description': 'Divides the first argument by subsequent arguments.'},
            {'name': 'min', 'title': 'min', 'description': 'Returns the minimum argument.'},
            {'name': 'max', 'title': 'max', 'description': 'Returns the maximum argument.'},
            {'name': 'round', 'title': 'round', 'description': 'Rounds a numeric value.'},
            {'name': 'int', 'title': 'int', 'description': 'Casts a value to int.'},
            {'name': 'float', 'title': 'float', 'description': 'Casts a value to float.'},
        ),
    },
    {
        'group': 'string',
        'functions': (
            {'name': 'str', 'title': 'str', 'description': 'Casts a value to string.'},
            {'name': 'lower', 'title': 'lower', 'description': 'Lower-cases a string.'},
            {'name': 'upper', 'title': 'upper', 'description': 'Upper-cases a string.'},
            {'name': 'concat', 'title': 'concat', 'description': 'Concatenates arguments into one string.'},
        ),
    },
    {
        'group': 'debug',
        'functions': (
            {'name': 'json', 'title': 'json', 'description': 'Serializes a value to JSON.'},
        ),
    },
)

ALLOWED_FUNCTIONS = {
    fn['name']
    for group in EXPRESSION_FUNCTION_GROUPS
    for fn in group['functions']
}


def parse_expr(expr: str, *, path: str) -> Any:
    """Parse and validate a single expression string without the `${}` wrapper."""
    expr = (expr or '').strip()
    if not expr:
        msg = 'Empty expression'
        raise CompileError(msg, path=path)

    tokens = _tokenize(expr)
    ast = _Parser(tokens, path=path).parse()
    _validate_ast(ast, path=path)
    return ast


def parse_required_expr_string(value: Any, *, path: str) -> Any:
    """Parse a required `${...}` expression string.

    The value must be a string containing exactly one expression and no extra
    template text.
    """
    if not isinstance(value, str):
        msg = 'Expected expression string like ${...}'
        raise CompileError(msg, path=path)

    s = value.strip()
    if not (s.startswith('${') and s.endswith('}')):
        msg = 'Expected expression string like ${...}'
        raise CompileError(msg, path=path)

    inner = s[2:-1].strip()
    return parse_expr(inner, path=path)


def _validate_ast(node: Any, *, path: str) -> None:
    if isinstance(node, RefExpr):
        if not node.path:
            msg = 'Invalid ref'
            raise CompileError(msg, path=path)
        if node.path[0] not in ALLOWED_REF_ROOTS:
            msg = 'Invalid expression. Use event.* / vars.* or allowlisted functions.'
            raise CompileError(msg, path=path)
        return

    if isinstance(node, CallExpr):
        if node.name not in ALLOWED_FUNCTIONS:
            msg = f'Function "{node.name}" is not allowed.'
            raise CompileError(msg, path=path)
        for a in node.args:
            _validate_ast(a, path=path)
        return

    if isinstance(node, (str, int, float, bool)) or node is None:
        return

    msg = 'Unsupported expression node'
    raise CompileError(msg, path=path)
