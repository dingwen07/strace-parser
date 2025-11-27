from typing import Any, List
from lark import Transformer, Tree, Token
import re
import json

# For extracting syscall names inside "<... clone resumed>"
_RESUMED_RE = re.compile(r"<\.\.\.\s+([a-zA-Z0-9_]+)\s+resumed>")

def _decode_c_string(s: str) -> str:
        """
        Convert a raw strace string token (which may or may not include surrounding quotes)
        into a proper decoded string.

        Handles:
          - Optional surrounding "..."       → strip them
          - C escapes: \", \\, \n, \t, \x3f, \177, \0, etc.
          - Works for both for '"\\x2fusr..."' and plain '\\x2fusr...' from fd<>
        """
        if not isinstance(s, str):
            return s

        original = s

        # Case 1: strace printed it as a quoted string → starts and ends with "
        if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
            s = s[1:-1]  # strip the quotes

        try:
            return s.encode("latin1").decode("unicode_escape")
        except Exception:
            # Fallback: return original
            return original

def convert(cls):
    def f(self, children):
        return cls(children[0])
    return f

def first_child():
    def f(self, children):
        return children[0]
    return f


class JsonTransformer(Transformer):

    # -------------------------------------
    # Top-level
    # -------------------------------------

    def start(self, children):
        return children

    def line(self, children):
        """
        Line can be:
            pid timestamp body
            timestamp body
        Body must ALWAYS become a dict.
        """
        if len(children) == 3:
            pid, ts, body = children
        else:
            pid = None
            ts, body = children

        # Ensure body is dict
        if not isinstance(body, dict):
            raise TypeError(f"Body transformer did not return dict: {body}")

        body["timestamp"] = ts
        if pid is not None:
            body["pid"] = pid

        return body

    # -------------------------------------
    # Syscall core
    # -------------------------------------

    def syscall(self, children):
        """
        syscall_name "(" args? ")" "=" result [duration]
        children can be:
          [name, args, result]
          [name, result]
          [name, args, result, duration]
          [name, result, duration]
        """
        name = children[0]

        # Case: second element is args (list)
        if len(children) >= 2 and isinstance(children[1], list):
            args = children[1]
            result = children[2] if len(children) > 2 else None
        else:
            # No args
            args = []
            result = children[1] if len(children) > 1 else None

        return {
            "type": "syscall",
            "status": "finished",
            "name": name,
            "args": args,
            "result": result,
        }

    def syscall_name(self, children):
        return str(children[0])

    def syscall_args(self, children):
        return children

    def syscall_result(self, children):
        return _decode_c_string(str(children[0]))

    # -------------------------------------
    # Unfinished call
    # -------------------------------------

    def unfinished_line(self, children):
        # children: [unfinished_syscall, "<unfinished ...>"]
        call = children[0]
        status = str(children[1])

        return {
            "type": "syscall",
            "status": "unfinished",
            "name": call["name"],
            "args": call["args"],
            "result": None,
        }

    def unfinished_syscall(self, children):
        """
        children = [name] or [name, args]
        """
        name = children[0]
        args = children[1] if len(children) > 1 else []
        return {
            "name": name,
            "args": args,
        }

    # -------------------------------------
    # Resumed call
    # -------------------------------------

    def resumed_line(self, children):
        """
        resumed_line : RESUMED_TAG _SP? resumed_tail
        resumed_tail: args?) "=" result (duration)?
        BUT strace often prints:
          <... rt_sigprocmask resumed>NULL, 8) = 0
        """
        tag = str(children[0])
        m = _RESUMED_RE.match(tag)
        name = m.group(1) if m else None

        tail = children[1] if len(children) > 1 else []

        # Parse tail into args/result
        args = []
        result = None

        if isinstance(tail, list) and len(tail) > 0:
            # tail pattern: [args, result] or just [result]
            if isinstance(tail[0], list):
                args = tail[0]
                result = tail[1] if len(tail) > 1 else None
            else:
                # No args
                result = tail[0]

        return {
            "type": "syscall",
            "status": "resumed",
            "name": name,
            "args": args,
            "result": result,
        }

    # -------------------------------------
    # Signal line
    # -------------------------------------

    def signal_line(self, children):
        sig = str(children[0])
        info = children[1]
        return {
            "type": "signal",
            "name": sig,
            "status": "signal",
            "info": info,
        }

    # -------------------------------------
    # Alert line
    # -------------------------------------

    def alert_body(self, children):
        return {
            "type": "alert",
            "status": "alert",
            "result": " ".join(str(c) for c in children),
        }

    # -------------------------------------
    # Struct / argument types
    # -------------------------------------

    def braced(self, children):
        fields = children[0]
        result = {}
        truncated = False

        for f in fields:
            if f == "...":
                truncated = True
                continue
            if isinstance(f, dict) and f.get("type") == "key_value":
                result[f["key"]] = f["value"]
            else:
                # Unexpected field type; keep raw
                result[str(f)] = f

        return {
            "type": "struct",
            "fields": result,
            "truncated": truncated
        }

    def bracketed(self, children):
        items = children[0]
        return {
            "type": "list",
            "items": items
        }


    def struct_fields(self, children):
        return children

    def kv(self, children):
        key, value = children
        return {
            "type": "key_value",
            "key": str(key),
            "value": value,
        }

    def function_like(self, children):
        name, args = children
        return {
            "type": "function",
            "name": str(name),
            "args": args,
        }
    
    def fd_with_path(self, children):
        """
        fd_with_path: DIGIT/NAME "<" RAWPATH ">"
        children => [fd, raw_path_token]
        """
        fd = str(children[0])
        raw = str(children[1])

        return {
            "type": "fd",
            "fd": fd,
            "path": _decode_c_string(raw),
        }

    def sigset(self, children):
        neg = False
        args = []
        for ch in children:
            if isinstance(ch, Token) and ch.type == "NEGATED":
                neg = True
            else:
                args.append(str(ch))
        return {
            "type": "sigset",
            "negated": neg,
            "args": args,
        }

    def c_expr(self, children):
        return _decode_c_string(str(children[0]))

    def plain_arg(self, children):
        return _decode_c_string(str(children[0]))

    # -------------------------------------
    # Misc
    # -------------------------------------

    body = first_child()
    timestamp = convert(float)

    def pid(self, children):
        return int(str(children[0]))


def to_json(tree: Tree) -> Any:
    return JsonTransformer().transform(tree)
