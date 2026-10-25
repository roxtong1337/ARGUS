"""A small YARA-like rule engine implemented in pure Python.

REA ships its own rule language so the toolkit has zero binary dependencies and
rules can be authored, reviewed and version-controlled as plain text. The
syntax is deliberately close to YARA to keep existing knowledge transferable:

    rule Example_Ransomware_Note
    {
        meta:
            author      = "rea-team"
            severity    = "high"
            score       = 35
            description = "Ransom note strings and a wallet address"

        strings:
            $note  = "your files have been encrypted" nocase
            $note2 = "recover your files" nocase
            $hex   = { 4D 5A ?? 90 }
            $rx    = /[A-Z]:\\\\Users\\\\[^\\\\]+\\\\Desktop/ nocase

        condition:
            (any of ($note*)) and 1 of them
    }

Supported condition vocabulary: ``any of them``, ``all of them``, ``N of them``,
``any/all/N of ($prefix*)``, boolean ``and``/``or``/``not``, parentheses, string
identifiers (``$a``), match counts (``#a``), ``filesize``, ``uint8/16/32(offset)``,
``entrypoint`` and the comparison operators ``== != < <= > >=``.

Not supported (yet): modules, private rules, rule references, ``for`` loops.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple


class RuleSyntaxError(ValueError):
    """Raised when a rule file cannot be parsed."""


# --------------------------------------------------------------------------
# String definitions
# --------------------------------------------------------------------------


@dataclass
class RuleString:
    identifier: str  # normalised, without the leading '$'
    kind: str  # "text" | "hex" | "regex"
    raw: str
    modifiers: set = field(default_factory=set)
    _matcher: Optional[re.Pattern] = None

    def compile(self) -> None:
        flags = 0
        if "nocase" in self.modifiers:
            flags |= re.IGNORECASE
        if "dotall" in self.modifiers:
            flags |= re.DOTALL

        if self.kind == "text":
            pattern = re.escape(self.raw.encode("utf-8", "surrogateescape"))
        elif self.kind == "hex":
            pattern = _hex_to_regex(self.raw)
        elif self.kind == "regex":
            try:
                pattern = self.raw.encode("utf-8", "surrogateescape")
                re.compile(pattern, flags)
            except re.error as exc:
                raise RuleSyntaxError(f"invalid regex in ${self.identifier}: {exc}") from exc
        else:
            raise RuleSyntaxError(f"unknown string kind: {self.kind}")

        self._matcher = re.compile(pattern, flags)

    def find(self, data: bytes) -> List[Tuple[int, bytes]]:
        if self._matcher is None:
            self.compile()
        hits = [(m.start(), m.group(0)) for m in self._matcher.finditer(data)]
        if "wide" in self.modifiers:
            wide = self._wide_pattern()
            hits.extend((m.start(), m.group(0)) for m in wide.finditer(data))
        return hits

    def _wide_pattern(self) -> re.Pattern:
        flags = re.IGNORECASE if "nocase" in self.modifiers else 0
        if self.kind == "text":
            body = b"".join(bytes([b, 0]) for b in self.raw.encode("utf-8", "surrogateescape"))
            return re.compile(re.escape(body), flags)
        pattern = self._matcher.pattern if self._matcher else b""
        wide = b"".join(bytes([b, 0]) for b in pattern)
        return re.compile(re.escape(wide), flags)


def _hex_to_regex(text: str) -> bytes:
    """Translate ``4D 5A ?? 90`` style patterns into a bytes regex."""
    tokens = text.split()
    parts: List[bytes] = []
    for tok in tokens:
        if tok in ("??", "?"):
            parts.append(b".")
        elif "?" in tok and len(tok) == 2:
            hi, lo = tok[0], tok[1]
            if hi == "?":
                parts.append(b"." if lo == "?" else _nibble_any_high(lo))
            elif lo == "?":
                parts.append(_nibble_any_low(hi))
            else:
                raise RuleSyntaxError(f"invalid hex token: {tok}")
        elif re.fullmatch(r"[0-9a-fA-F]{2}", tok):
            parts.append(re.escape(bytes([int(tok, 16)])))
        elif tok in ("(", ")", "|"):
            continue
        else:
            raise RuleSyntaxError(f"invalid hex token: {tok}")
    if not parts:
        raise RuleSyntaxError("empty hex pattern")
    return b"".join(parts)


def _nibble_any_high(lo: str) -> bytes:
    # low nibble fixed, high nibble free: bytes 0x?lo
    value = int(lo, 16)
    options = [value + 16 * h for h in range(16)]
    return b"(?:" + b"|".join(re.escape(bytes([o])) for o in options) + b")"


def _nibble_any_low(hi: str) -> bytes:
    value = int(hi, 16) << 4
    options = [value + l for l in range(16)]
    return b"(?:" + b"|".join(re.escape(bytes([o])) for o in options) + b")"


# --------------------------------------------------------------------------
# Rule model
# --------------------------------------------------------------------------


@dataclass
class Rule:
    name: str
    strings: List[RuleString] = field(default_factory=list)
    condition: str = "any of them"
    meta: Dict[str, str] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    source: str = "<inline>"
    compiled_condition: object = None

    @property
    def severity(self) -> str:
        return (self.meta.get("severity") or "medium").lower()

    @property
    def score(self) -> int:
        try:
            return int(self.meta.get("score", 0))
        except (TypeError, ValueError):
            return 0

    @property
    def description(self) -> str:
        return self.meta.get("description", "")

    def string_map(self) -> Dict[str, RuleString]:
        return {s.identifier: s for s in self.strings}


@dataclass
class RuleMatch:
    rule: Rule
    matched_strings: Dict[str, int]
    evidence: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------

_KNOWN_MODIFIERS = {"nocase", "wide", "ascii", "fullword", "dotall"}

_PUNCT = set("{}:=(),*<>!")

_HEX_LIKE_RE = re.compile(r"^[\s0-9a-fA-F?|()]+$")


class _RuleToken:
    __slots__ = ("kind", "value")

    def __init__(self, kind: str, value: str):
        self.kind = kind
        self.value = value

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{self.kind}:{self.value!r}>"


def _tokenize_rules(text: str, source: str) -> List[_RuleToken]:
    """Tokenize a rule file into a flat stream.

    A ``{`` is emitted as a HEX token when its contents look like a byte pattern
    and as a PUNCT token otherwise, which is what lets the same character open a
    rule body and delimit a hex string without a context-sensitive grammar.
    """
    tokens: List[_RuleToken] = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]

        if c in " \t\r\n":
            i += 1
            continue

        if text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end + 1
            continue

        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue

        if c == '"':
            j = i + 1
            buf = []
            while j < n:
                if text[j] == "\\" and j + 1 < n:
                    buf.append(text[j : j + 2])
                    j += 2
                    continue
                if text[j] == '"':
                    break
                buf.append(text[j])
                j += 1
            if j >= n:
                raise RuleSyntaxError(f"{source}: unterminated string literal")
            tokens.append(_RuleToken("string", "".join(buf)))
            i = j + 1
            continue

        if c == "{":
            end = text.find("}", i + 1)
            if end != -1:
                inner = text[i + 1 : end]
                if _HEX_LIKE_RE.match(inner) and any(ch.isalnum() or ch == "?" for ch in inner):
                    tokens.append(_RuleToken("hex", inner))
                    i = end + 1
                    continue
            tokens.append(_RuleToken("punct", "{"))
            i += 1
            continue

        if c == "/":
            j = i + 1
            buf = []
            while j < n:
                if text[j] == "\\" and j + 1 < n:
                    buf.append(text[j : j + 2])
                    j += 2
                    continue
                if text[j] == "/":
                    break
                buf.append(text[j])
                j += 1
            if j >= n:
                raise RuleSyntaxError(f"{source}: unterminated regex literal")
            tokens.append(_RuleToken("regex", "".join(buf)))
            i = j + 1
            continue

        if c == "$":
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] == "_"):
                j += 1
            if j < n and text[j] == "*":
                j += 1
            tokens.append(_RuleToken("strid", text[i:j]))
            i = j
            continue

        if c == "#":
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] == "_"):
                j += 1
            tokens.append(_RuleToken("count", text[i:j]))
            i = j
            continue

        if c.isdigit():
            j = i
            while j < n and (text[j].isalnum() or text[j] == "."):
                j += 1
            tokens.append(_RuleToken("number", text[i:j]))
            i = j
            continue

        if c.isalpha() or c == "_":
            j = i
            while j < n and (text[j].isalnum() or text[j] == "_"):
                j += 1
            tokens.append(_RuleToken("ident", text[i:j]))
            i = j
            continue

        if c in _PUNCT or c == "-":
            if i + 1 < n and text[i : i + 2] in ("==", "!=", "<=", ">="):
                tokens.append(_RuleToken("punct", text[i : i + 2]))
                i += 2
                continue
            tokens.append(_RuleToken("punct", c))
            i += 1
            continue

        raise RuleSyntaxError(f"{source}: unexpected character {c!r}")

    return tokens


class _RuleParser:
    def __init__(self, tokens: List[_RuleToken], source: str):
        self.tokens = tokens
        self.pos = 0
        self.source = source

    def peek(self, offset: int = 0) -> Optional[_RuleToken]:
        idx = self.pos + offset
        return self.tokens[idx] if idx < len(self.tokens) else None

    def next(self) -> _RuleToken:
        if self.pos >= len(self.tokens):
            raise RuleSyntaxError(f"{self.source}: unexpected end of rule file")
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def at(self, kind: str, value: Optional[str] = None) -> bool:
        tok = self.peek()
        if tok is None or tok.kind != kind:
            return False
        return value is None or tok.value == value

    def parse_rules(self) -> List[Rule]:
        rules: List[Rule] = []
        while self.peek() is not None:
            tok = self.peek()
            if tok.kind == "ident" and tok.value == "private" and self.peek(1) and self.peek(1).value == "rule":
                self.next()
                continue
            if tok.kind == "ident" and tok.value == "rule":
                rules.append(self.parse_rule())
                continue
            self.next()
        if not rules:
            raise RuleSyntaxError(f"{self.source}: no rules found")
        return rules

    def parse_rule(self) -> Rule:
        self.next()  # 'rule'
        name_tok = self.next()
        if name_tok.kind != "ident":
            raise RuleSyntaxError(f"{self.source}: expected rule name, got {name_tok.value!r}")
        rule = Rule(name=name_tok.value, source=self.source)

        while self.at("punct", ":") or self.at("punct", ","):
            self.next()
            while self.peek() and self.peek().kind == "ident":
                rule.tags.append(self.next().value)

        if not self.at("punct", "{"):
            raise RuleSyntaxError(f"{self.source}: expected '{{' after rule {rule.name}")
        self.next()

        section = None
        condition_tokens: List[str] = []
        while True:
            tok = self.peek()
            if tok is None:
                raise RuleSyntaxError(f"{self.source}: unterminated rule {rule.name}")
            if tok.kind == "punct" and tok.value == "}":
                self.next()
                break
            if (
                tok.kind == "ident"
                and tok.value in ("meta", "strings", "condition")
                and self.peek(1) is not None
                and self.peek(1).value == ":"
            ):
                section = tok.value
                self.next()
                self.next()
                continue

            if section == "meta":
                key = self.next()
                if not self.at("punct", "="):
                    raise RuleSyntaxError(f"{self.source}: expected '=' in meta of {rule.name}")
                self.next()
                value = self.next()
                rule.meta[key.value] = value.value
            elif section == "strings":
                ident = self.next()
                if ident.kind != "strid":
                    raise RuleSyntaxError(f"{self.source}: expected $identifier, got {ident.value!r}")
                if not self.at("punct", "="):
                    raise RuleSyntaxError(f"{self.source}: expected '=' after {ident.value}")
                self.next()
                value = self.next()
                if value.kind == "string":
                    kind, raw = "text", _unescape(value.value)
                elif value.kind == "hex":
                    kind, raw = "hex", value.value
                elif value.kind == "regex":
                    kind, raw = "regex", value.value
                else:
                    raise RuleSyntaxError(f"{self.source}: bad string value for {ident.value}")
                mods = set()
                while self.peek() and self.peek().kind == "ident" and self.peek().value in _KNOWN_MODIFIERS:
                    mods.add(self.next().value)
                rule.strings.append(
                    RuleString(identifier=ident.value.lstrip("$"), kind=kind, raw=raw, modifiers=mods)
                )
            elif section == "condition":
                tok = self.next()
                if tok.kind == "string":
                    condition_tokens.append(json.dumps(tok.value))
                else:
                    condition_tokens.append(tok.value)
            else:
                raise RuleSyntaxError(f"{self.source}: content outside a section in {rule.name}")

        if condition_tokens:
            rule.condition = " ".join(condition_tokens)

        for rs in rule.strings:
            rs.compile()
        rule.compiled_condition = parse_condition(rule.condition, self.source)
        return rule


def parse_rules(text: str, source: str = "<inline>") -> List[Rule]:
    """Parse a rule file containing one or more ``rule`` blocks."""
    tokens = _tokenize_rules(text, source)
    return _RuleParser(tokens, source).parse_rules()


def _unescape(text: str) -> str:
    out = []
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            mapping = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", '"': '"', "0": "\0"}
            out.append(mapping.get(nxt, nxt))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


# --------------------------------------------------------------------------
# Condition parsing
# --------------------------------------------------------------------------


@dataclass
class Node:
    kind: str
    value: object = None
    children: List["Node"] = field(default_factory=list)


_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<hash>\#[A-Za-z_]\w*)
  | (?P<str_id>\$[A-Za-z_]\w*(?:\*)?)
  | (?P<number>0x[0-9a-fA-F]+|\d+(?:\.\d+)?(?:KB|MB|GB)?)
  | (?P<string>"(?:[^"\\]|\\.)*")
  | (?P<op>==|!=|<=|>=|<|>|\(|\)|,)
  | (?P<ident>[A-Za-z_]\w*)
    """,
    re.VERBOSE,
)


def _tokenize(condition: str) -> List[Tuple[str, str]]:
    tokens: List[Tuple[str, str]] = []
    pos = 0
    while pos < len(condition):
        m = _TOKEN_RE.match(condition, pos)
        if not m:
            raise RuleSyntaxError(f"unexpected character in condition: {condition[pos]!r}")
        pos = m.end()
        kind = m.lastgroup
        if kind == "ws":
            continue
        tokens.append((kind, m.group()))
    return tokens


class ConditionParser:
    def __init__(self, tokens: List[Tuple[str, str]], source: str):
        self.tokens = tokens
        self.pos = 0
        self.source = source

    def peek(self) -> Optional[Tuple[str, str]]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def next(self) -> Tuple[str, str]:
        if self.pos >= len(self.tokens):
            raise RuleSyntaxError(f"{self.source}: unexpected end of condition")
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def expect(self, value: str) -> None:
        tok = self.next()
        if tok[1].lower() != value:
            raise RuleSyntaxError(f"{self.source}: expected {value!r}, got {tok[1]!r}")

    def parse(self) -> Node:
        node = self.parse_or()
        if self.peek() is not None:
            raise RuleSyntaxError(f"{self.source}: trailing tokens in condition: {self.peek()[1]!r}")
        return node

    def parse_or(self) -> Node:
        node = self.parse_and()
        while self.peek() and self.peek()[1].lower() == "or":
            self.next()
            node = Node("or", children=[node, self.parse_and()])
        return node

    def parse_and(self) -> Node:
        node = self.parse_not()
        while self.peek() and self.peek()[1].lower() == "and":
            self.next()
            node = Node("and", children=[node, self.parse_not()])
        return node

    def parse_not(self) -> Node:
        tok = self.peek()
        if tok and tok[1].lower() == "not":
            self.next()
            return Node("not", children=[self.parse_not()])
        return self.parse_comparison()

    def parse_comparison(self) -> Node:
        left = self.parse_primary()
        tok = self.peek()
        if tok and tok[0] == "op" and tok[1] in ("==", "!=", "<", "<=", ">", ">="):
            op = self.next()[1]
            right = self.parse_primary()
            return Node("cmp", value=op, children=[left, right])
        return left

    def parse_primary(self) -> Node:
        tok = self.next()
        kind, value = tok

        if kind == "op" and value == "(":
            node = self.parse_or()
            self.expect(")")
            return node
        if kind == "str_id":
            return Node("string", value=value[1:].rstrip("*"), children=[])
        if kind == "hash":
            return Node("count", value=value[1:])
        if kind == "number":
            return Node("number", value=_parse_number(value))
        if kind == "string":
            return Node("literal", value=_unescape(value[1:-1]))
        if kind == "ident":
            low = value.lower()
            if low in ("any", "all"):
                self.expect("of")
                return Node("of", value=("any" if low == "any" else "all"), children=[self.parse_string_set()])
            if low == "them":
                return Node("them")
            if low in ("filesize", "entrypoint"):
                return Node(low)
            if low in ("uint8", "uint16", "uint32", "uint64"):
                self.expect("(")
                arg = self.parse_or()
                self.expect(")")
                return Node(low, children=[arg])
            raise RuleSyntaxError(f"{self.source}: unexpected identifier {value!r}")
        if kind == "number":
            return Node("number", value=_parse_number(value))
        raise RuleSyntaxError(f"{self.source}: unexpected token {value!r}")

    def parse_string_set(self) -> Node:
        tok = self.next()
        if tok[1].lower() == "them":
            return Node("them")
        if tok[1] != "(":
            raise RuleSyntaxError(f"{self.source}: expected '(' or 'them', got {tok[1]!r}")
        identifiers: List[str] = []
        wildcards: List[str] = []
        while True:
            nxt = self.next()
            if nxt[0] == "str_id":
                if nxt[1].endswith("*"):
                    wildcards.append(nxt[1][1:-1])
                else:
                    identifiers.append(nxt[1][1:])
            else:
                raise RuleSyntaxError(f"{self.source}: expected string identifier, got {nxt[1]!r}")
            sep = self.peek()
            if sep and sep[1] == ",":
                self.next()
                continue
            break
        self.expect(")")
        return Node("set", children=[Node("ids", value=identifiers), Node("prefixes", value=wildcards)])


def _parse_number(text: str):
    if text.startswith("0x"):
        return int(text, 16)
    m = re.fullmatch(r"(\d+(?:\.\d+)?)(KB|MB|GB)?", text)
    if not m:
        raise RuleSyntaxError(f"invalid number: {text}")
    value = float(m.group(1))
    mult = {"KB": 1024, "MB": 1024**2, "GB": 1024**3, None: 1}[m.group(2)]
    return int(value * mult) if m.group(2) else (value if "." in m.group(1) else int(value))


def parse_condition(condition: str, source: str = "<inline>") -> Node:
    # Allow the leading count form "3 of them" which the tokenizer sees as
    # number + ident('of').
    tokens = _tokenize(condition)
    # Rewrite "<number> of ..." into "<n> of ..." handled by parser below.
    parser = _ConditionParserWithCount(tokens, source)
    return parser.parse()


class _ConditionParserWithCount(ConditionParser):
    def parse_primary(self) -> Node:
        tok = self.peek()
        if tok and tok[0] == "number":
            nxt = self.tokens[self.pos + 1] if self.pos + 1 < len(self.tokens) else None
            if nxt and nxt[0] == "ident" and nxt[1].lower() == "of":
                self.next()
                self.next()
                return Node(
                    "of",
                    value=_parse_number(tok[1]),
                    children=[self.parse_string_set()],
                )
        return super().parse_primary()


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------


class EvalContext:
    def __init__(self, data: bytes, matches: Dict[str, int], all_ids: Sequence[str]):
        self.data = data
        self.matches = matches
        self.all_ids = list(all_ids)


def evaluate(node: Node, ctx: EvalContext):
    kind = node.kind

    if kind == "or":
        return any(bool(evaluate(c, ctx)) for c in node.children)
    if kind == "and":
        return all(bool(evaluate(c, ctx)) for c in node.children)
    if kind == "not":
        return not bool(evaluate(node.children[0], ctx))
    if kind == "string":
        return ctx.matches.get(node.value, 0) > 0
    if kind == "count":
        return ctx.matches.get(node.value, 0)
    if kind == "number":
        return node.value
    if kind == "literal":
        return node.value
    if kind == "filesize":
        return len(ctx.data)
    if kind == "entrypoint":
        return 0
    if kind in ("uint8", "uint16", "uint32", "uint64"):
        offset = int(evaluate(node.children[0], ctx) or 0)
        width = int(kind[4:]) // 8
        if offset < 0 or offset + width > len(ctx.data):
            return 0
        return int.from_bytes(ctx.data[offset : offset + width], "little")
    if kind == "them":
        return bool(ctx.all_ids)
    if kind == "set":
        return _resolve_set(node, ctx)
    if kind == "of":
        matched = _resolve_set(node.children[0], ctx)
        if node.value == "any":
            return len(matched) >= 1
        if node.value == "all":
            total = len(_set_members(node.children[0], ctx))
            return total > 0 and len(matched) >= total
        return len(matched) >= int(node.value)
    if kind == "cmp":
        left = evaluate(node.children[0], ctx)
        right = evaluate(node.children[1], ctx)
        return _compare(node.value, left, right)

    raise RuleSyntaxError(f"cannot evaluate node kind {kind!r}")


def _compare(op: str, left, right) -> bool:
    if op == "==":
        return left == right
    if op == "!=":
        return left != right
    try:
        if op == "<":
            return left < right
        if op == "<=":
            return left <= right
        if op == ">":
            return left > right
        if op == ">=":
            return left >= right
    except TypeError:
        return False
    return False


def _set_members(node: Node, ctx: EvalContext) -> List[str]:
    if node.kind == "them":
        return list(ctx.all_ids)
    ids_node = next(c for c in node.children if c.kind == "ids")
    prefixes_node = next(c for c in node.children if c.kind == "prefixes")
    members = list(ids_node.value)
    for prefix in prefixes_node.value:
        members.extend(i for i in ctx.all_ids if i.startswith(prefix))
    # Keep only identifiers that are actually matched at least once for "N of"
    # semantics; unmatched ids still count as members but never as matched.
    return members


def _resolve_set(node: Node, ctx: EvalContext) -> List[str]:
    members = _set_members(node, ctx)
    return [m for m in members if ctx.matches.get(m, 0) > 0]


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------


def scan(data: bytes, rules: Sequence[Rule]) -> List[RuleMatch]:
    """Evaluate every rule against ``data`` and return the matches."""
    results: List[RuleMatch] = []
    for rule in rules:
        smap = rule.string_map()
        matches: Dict[str, int] = {}
        evidence: List[str] = []
        for identifier, rs in smap.items():
            try:
                hits = rs.find(data)
            except re.error:
                hits = []
            if hits:
                matches[identifier] = len(hits)
                sample = hits[0][1][:64]
                try:
                    evidence.append(f"${identifier} @ 0x{hits[0][0]:x}: {sample.decode('utf-8', 'replace')!r}")
                except Exception:
                    evidence.append(f"${identifier} @ 0x{hits[0][0]:x}")

        ctx = EvalContext(data, matches, list(smap.keys()))
        try:
            if not evaluate(rule.compiled_condition, ctx):
                continue
        except RuleSyntaxError:
            continue

        results.append(RuleMatch(rule=rule, matched_strings=matches, evidence=evidence))
    return results


def load_rule_file(path: str) -> List[Rule]:
    with open(path, "r", encoding="utf-8") as fh:
        return parse_rules(fh.read(), source=path)


def load_rule_dir(path: str) -> List[Rule]:
    rules: List[Rule] = []
    if not os.path.isdir(path):
        return rules
    for entry in sorted(os.listdir(path)):
        if entry.endswith((".rea", ".yar", ".yara")):
            rules.extend(load_rule_file(os.path.join(path, entry)))
    return rules
