# workflows2/compiler/expr.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .errors import CompileError


# ----------------------------- AST nodes ----------------------------- #

@dataclass(frozen=True)
class RefExpr:
    path: list[str]  # e.g. ["event","device","common_name"]


@dataclass(frozen=True)
class CallExpr:
    name: str
    args: list[Any]  # args are AST nodes or literals


# ----------------------------- tokenization ----------------------------- #

@dataclass(frozen=True)
class Token:
    typ: str
    val: str
    pos: int


def _tokenize(s: str) -> list[Token]:
    tokens: list[Token] = []
    i = 0
    n = len(s)

    def add(typ: str, val: str, pos: int) -> None:
        tokens.append(Token(typ=typ, val=val, pos=pos))

    while i < n:
        ch = s[i]

        # whitespace
        if ch.isspace():
            i += 1
            continue

        # punctuation
        if ch in "(),.":
            add(ch, ch, i)
            i += 1
            continue

        # string literal (single or double)
        if ch in ("'", '"'):
            quote = ch
            start = i
            i += 1
            buf: list[str] = []
            while i < n:
                c = s[i]
                if c == "\\":
                    if i + 1 >= n:
                        raise CompileError("Unterminated escape sequence in string literal")
                    buf.append(s[i + 1])
                    i += 2
                    continue
                if c == quote:
                    i += 1
                    add("STRING", "".join(buf), start)
                    break
                buf.append(c)
                i += 1
            else:
                raise CompileError("Unterminated string literal")
            continue

        # number literal: int or float
        if ch.isdigit() or (ch == "-" and i + 1 < n and s[i + 1].isdigit()):
            start = i
            i += 1
            has_dot = False
            while i < n:
                c = s[i]
                if c.isdigit():
                    i += 1
                    continue
                if c == "." and not has_dot:
                    has_dot = True
                    i += 1
                    continue
                break
            add("NUMBER", s[start:i], start)
            continue

        # identifier
        if ch.isalpha() or ch == "_":
            start = i
            i += 1
            while i < n and (s[i].isalnum() or s[i] == "_"):
                i += 1
            add("IDENT", s[start:i], start)
            continue

        raise CompileError(f"Unexpected character '{ch}' in expression")

    add("EOF", "", n)
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
            raise CompileError(f"Expected {typ} but found {t.typ}", path=self.path)
        self.i += 1
        return t

    def maybe(self, typ: str) -> Token | None:
        if self.cur().typ == typ:
            return self.eat(typ)
        return None

    def parse(self) -> Any:
        expr = self.parse_primary()
        if self.cur().typ != "EOF":
            raise CompileError("Unexpected trailing tokens in expression", path=self.path)
        return expr

    def parse_primary(self) -> Any:
        t = self.cur()

        if t.typ == "IDENT":
            ident = self.eat("IDENT").val

            # literals by identifier
            low = ident.lower()
            if low == "true":
                return True
            if low == "false":
                return False
            if low == "null":
                return None

            # call: ident(...)
            if self.cur().typ == "(":
                self.eat("(")
                args: list[Any] = []
                if self.cur().typ != ")":
                    while True:
                        args.append(self.parse_primary())
                        if self.maybe(","):
                            continue
                        break
                self.eat(")")
                return CallExpr(name=ident, args=args)

            # ref: ident(.ident)*
            path = [ident]
            while self.maybe("."):
                seg = self.eat("IDENT").val
                path.append(seg)
            return RefExpr(path=path)

        if t.typ == "NUMBER":
            raw = self.eat("NUMBER").val
            try:
                if "." in raw:
                    return float(raw)
                return int(raw)
            except ValueError as e:
                raise CompileError("Invalid number literal", path=self.path) from e

        if t.typ == "STRING":
            return self.eat("STRING").val

        raise CompileError(f"Invalid expression token: {t.typ}", path=self.path)


# ----------------------------- allowlist + public API ----------------------------- #

ALLOWED_REF_ROOTS = {"event", "vars"}

ALLOWED_FUNCTIONS = {
    # numeric
    "add",
    "sub",
    "mul",
    "div",
    "min",
    "max",
    "round",
    "int",
    "float",
    # string
    "str",
    "lower",
    "upper",
    "concat",
    # debug/serialization
    "json",
}


def parse_expr(expr: str, *, path: str) -> Any:
    """
    Parse and validate a single expression string (no surrounding ${}).
    """
    expr = (expr or "").strip()
    if not expr:
        raise CompileError("Empty expression", path=path)

    tokens = _tokenize(expr)
    ast = _Parser(tokens, path=path).parse()
    _validate_ast(ast, path=path)
    return ast


def parse_required_expr_string(value: Any, *, path: str) -> Any:
    """
    Requires value to be a string of the form: ${ ... }
    And requires it to be a *single* expression (no template text).
    Returns parsed+validated AST.
    """
    if not isinstance(value, str):
        raise CompileError("Expected expression string like ${...}", path=path)

    s = value.strip()
    if not (s.startswith("${") and s.endswith("}")):
        raise CompileError("Expected expression string like ${...}", path=path)

    inner = s[2:-1].strip()
    return parse_expr(inner, path=path)


def _validate_ast(node: Any, *, path: str) -> None:
    if isinstance(node, RefExpr):
        if not node.path:
            raise CompileError("Invalid ref", path=path)
        if node.path[0] not in ALLOWED_REF_ROOTS:
            raise CompileError(
                "Invalid expression. Use event.* / vars.* or allowlisted functions.",
                path=path,
            )
        return

    if isinstance(node, CallExpr):
        if node.name not in ALLOWED_FUNCTIONS:
            raise CompileError(
                f'Function "{node.name}" is not allowed.',
                path=path,
            )
        for a in node.args:
            _validate_ast(a, path=path)
        return

    # literals
    if isinstance(node, (str, int, float, bool)) or node is None:
        return

    raise CompileError("Unsupported expression node", path=path)
