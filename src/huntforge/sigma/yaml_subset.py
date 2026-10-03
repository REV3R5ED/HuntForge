"""Minimal YAML-subset parser for Sigma-style rules (v0.6).

PyYAML is not in the standard library and HuntForge is stdlib-only,
so Sigma YAML rules go through this small hand-written parser. It is
deliberately *not* a YAML parser — it handles exactly the flat shapes
Sigma rules use, and fails loudly on anything else.

Supported:
  - block mappings: ``key: value`` and ``key:`` with a nested block
  - block sequences: ``- item`` and ``- key: value`` (inline map head,
    with continuation lines forming the rest of the map)
  - scalars: bare strings, single/double-quoted strings (with basic
    escapes in double quotes), integers, ``true``/``false``,
    ``null``/``~``/empty
  - comments (``#`` outside quotes) and blank lines
  - spaces for indentation (any consistent width per level)

NOT supported (each raises :class:`YamlSubsetError` naming the
construct): tabs, flow collections (``{}`` / ``[]``), block scalars
(``|`` / ``>``), anchors/aliases (``&`` / ``*``), tags (``!``),
directives (``%``), duplicate mapping keys, multi-line quoted
scalars.
"""

from __future__ import annotations


class YamlSubsetError(ValueError):
    """A Sigma YAML rule used a construct outside the supported subset."""


def _strip_comment(line: str) -> str:
    """Remove a ``#`` comment, respecting single/double quotes."""
    in_single = in_double = False
    i = 0
    while i < len(line):
        char = line[i]
        if char == "\\" and in_double:
            i += 2
            continue
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            # A comment starts at # when preceded by whitespace or at
            # the start of the (already left-stripped) content.
            if i == 0 or line[i - 1] in (" ", "\t"):
                return line[:i].rstrip()
        i += 1
    return line


def _split_key(content: str, lineno: int) -> tuple[str, str]:
    """Split ``key: value`` on the first colon outside quotes.

    Returns ``(key, value)``; ``value`` is ``""`` for ``key:``.
    """
    in_single = in_double = False
    i = 0
    while i < len(content):
        char = content[i]
        if char == "\\" and in_double:
            i += 2
            continue
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == ":" and not in_single and not in_double:
            after = content[i + 1 :]
            if after == "" or after[0] in (" ", "\t"):
                key = content[:i].strip()
                return _unquote_key(key, lineno), after.strip()
        i += 1
    raise YamlSubsetError(f"line {lineno}: expected 'key: value', got {content!r}")


def _unquote_key(key: str, lineno: int) -> str:
    if len(key) >= 2 and key[0] == key[-1] and key[0] in ("'", '"'):
        return _parse_scalar(key, lineno)  # type: ignore[return-value]
    if not key:
        raise YamlSubsetError(f"line {lineno}: empty mapping key")
    return key


def _parse_scalar(text: str, lineno: int) -> str | int | bool | None:
    """Parse one scalar; raises on unsupported YAML constructs."""
    if not text:
        return None
    first = text[0]
    if first in "{[":
        raise YamlSubsetError(
            f"line {lineno}: flow collections are not supported "
            f"(use block style): {text!r}"
        )
    if first in "|>":
        raise YamlSubsetError(f"line {lineno}: block scalars (|, >) are not supported")
    if first in "&*!%@`":
        raise YamlSubsetError(
            f"line {lineno}: anchors, aliases, tags and directives "
            f"are not supported: {text!r}"
        )
    if first == '"':
        if len(text) < 2 or not text.endswith('"'):
            raise YamlSubsetError(
                f"line {lineno}: unterminated double-quoted string "
                f"(multi-line strings are not supported)"
            )
        return _unescape(text[1:-1], lineno)
    if first == "'":
        if len(text) < 2 or not text.endswith("'"):
            raise YamlSubsetError(f"line {lineno}: unterminated single-quoted string")
        return text[1:-1].replace("''", "'")
    lowered = text.lower()
    if lowered in ("null", "~", "none"):
        return None
    if lowered in ("true", "false"):
        return lowered == "true"
    try:
        return int(text)
    except ValueError:
        pass
    # A bare scalar containing ": " is almost certainly a mis-indented
    # mapping; fail loudly instead of swallowing it as a string.
    return text


def _unescape(text: str, lineno: int) -> str:
    out: list[str] = []
    i = 0
    simple = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "0": "\0"}
    while i < len(text):
        char = text[i]
        if char == "\\":
            if i + 1 >= len(text):
                raise YamlSubsetError(f"line {lineno}: trailing backslash in string")
            nxt = text[i + 1]
            if nxt in simple:
                out.append(simple[nxt])
            else:
                raise YamlSubsetError(
                    f"line {lineno}: unsupported escape '\\{nxt}' "
                    f'(supported: \\n \\t \\r \\\\ \\" \\0)'
                )
            i += 2
        else:
            out.append(char)
            i += 1
    return "".join(out)


def _lex(text: str) -> list[tuple[int, int, str]]:
    """Split into (lineno, indent, content); blank/comment lines dropped."""
    lines: list[tuple[int, int, str]] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped:
            continue
        leading = raw[: len(raw) - len(raw.lstrip())]
        if "\t" in leading:
            raise YamlSubsetError(
                f"line {lineno}: tabs are not allowed for indentation"
            )
        stripped_left = raw.lstrip(" ")
        if stripped_left.startswith("#"):
            continue
        indent = len(leading)
        content = _strip_comment(stripped_left).strip()
        if content:
            lines.append((lineno, indent, content))
    return lines


def _parse_block(
    lines: list[tuple[int, int, str]], pos: int, indent: int
) -> tuple[object, int]:
    """Parse one block (map or list) at ``indent``; returns (value, pos)."""
    content = lines[pos][2]
    if content == "-" or content.startswith("- "):
        return _parse_list(lines, pos, indent)
    return _parse_map(lines, pos, indent)


def _parse_map(
    lines: list[tuple[int, int, str]], pos: int, indent: int
) -> tuple[dict[str, object], int]:
    mapping: dict[str, object] = {}
    while pos < len(lines):
        lineno, ind, content = lines[pos]
        if ind < indent:
            break
        if ind > indent:
            raise YamlSubsetError(
                f"line {lineno}: unexpected indentation "
                f"(expected {indent} spaces, got {ind})"
            )
        if content == "-" or content.startswith("- "):
            raise YamlSubsetError(
                f"line {lineno}: expected 'key: value', found a list item"
            )
        key, value = _split_key(content, lineno)
        if key in mapping:
            raise YamlSubsetError(f"line {lineno}: duplicate key {key!r}")
        if value:
            mapping[key] = _parse_scalar(value, lineno)
            pos += 1
        else:
            pos += 1
            if pos < len(lines) and lines[pos][1] > indent:
                child, pos = _parse_block(lines, pos, lines[pos][1])
                mapping[key] = child
            else:
                mapping[key] = None
    return mapping, pos


def _parse_list(
    lines: list[tuple[int, int, str]], pos: int, indent: int
) -> tuple[list[object], int]:
    items: list[object] = []
    while pos < len(lines):
        lineno, ind, content = lines[pos]
        if ind < indent:
            break
        if ind > indent:
            raise YamlSubsetError(
                f"line {lineno}: unexpected indentation in list "
                f"(expected {indent} spaces, got {ind})"
            )
        if not (content == "-" or content.startswith("- ")):
            raise YamlSubsetError(
                f"line {lineno}: expected a '- item' line, got {content!r}"
            )
        rest = content[1:].strip()
        pos += 1
        if not rest:
            if pos < len(lines) and lines[pos][1] > indent:
                child, pos = _parse_block(lines, pos, lines[pos][1])
                items.append(child)
            else:
                items.append(None)
            continue
        # Inline map head: "- key: value" plus deeper continuation lines.
        if ":" in rest and not rest.startswith(('"', "'")):
            try:
                key, value = _split_key(rest, lineno)
            except YamlSubsetError:
                key, value = "", ""
            if key:
                item_map: dict[str, object] = {}
                item_map[key] = _parse_scalar(value, lineno) if value else None
                if not value:
                    if pos < len(lines) and lines[pos][1] > indent:
                        child, pos = _parse_block(lines, pos, lines[pos][1])
                        if not isinstance(child, dict):
                            raise YamlSubsetError(
                                f"line {lineno}: expected mapping entries "
                                f"after '- {key}:'"
                            )
                        item_map.update(child)
                else:
                    while pos < len(lines) and lines[pos][1] > indent:
                        cline, cind, ccontent = lines[pos]
                        if ccontent == "-" or ccontent.startswith("- "):
                            break
                        ckey, cvalue = _split_key(ccontent, cline)
                        if ckey in item_map:
                            raise YamlSubsetError(
                                f"line {cline}: duplicate key {ckey!r}"
                            )
                        if cvalue:
                            item_map[ckey] = _parse_scalar(cvalue, cline)
                            pos += 1
                        else:
                            pos += 1
                            if pos < len(lines) and lines[pos][1] > cind:
                                grandchild, pos = _parse_block(
                                    lines, pos, lines[pos][1]
                                )
                                item_map[ckey] = grandchild
                            else:
                                item_map[ckey] = None
                items.append(item_map)
                continue
        items.append(_parse_scalar(rest, lineno))
    return items, pos


def parse(text: str) -> object:
    """Parse a YAML-subset document; see the module docstring for limits."""
    lines = _lex(text)
    if not lines:
        raise YamlSubsetError("empty document")
    value, pos = _parse_block(lines, 0, lines[0][1])
    if pos != len(lines):
        lineno = lines[pos][0]
        raise YamlSubsetError(f"line {lineno}: unexpected content after document root")
    return value
