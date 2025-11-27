from typing import Any
from lark import Transformer, Tree, Token


def convert(cls):
    def f(self, children):
        return cls(children[0])
    return f


def first_child():
    def f(self, children):
        return children[0]
    return f


class JsonTransformer(Transformer):
    # -------------------------
    # Top-level
    # -------------------------
    def start(self, children):
        return children

    def line(self, children):
        timestamp, body = children
        body["timestamp"] = timestamp
        return body

    # -------------------------
    # Syscall core
    # -------------------------
    def syscall(self, children):
        name, args, result = children
        return {
            "type": "syscall",
            "name": name,
            "args": args,
            "result": result,
        }

    # grammar: syscall_name : NAME
    def syscall_name(self, children):
        # children[0] is a NAME token
        return str(children[0])

    # grammar: syscall_args : syscall_arg? ("," _SP? syscall_arg)*
    def syscall_args(self, children):
        # just a flat list of already-transformed args
        return children

    # grammar: syscall_result : /.../
    def syscall_result(self, children):
        return str(children[0])

    # -------------------------
    # NEW: signal line
    # -------------------------
    # signal_line : "---" _SP SIG_NAME _SP braced _SP "---"
    def signal_line(self, children):
        sig_name = children[0]      # SIG_NAME token value
        braced = children[1]        # {"type": "braced", ...}
        return {
            "type": "signal",
            "signal": str(sig_name),
            "info": braced,
        }

    # -------------------------
    # NEW: resumed line
    # -------------------------
    # resumed_line : "<... resumed>" _SP syscall _SP*
    def resumed_line(self, children):
        return {
            "type": "resumed",
            "syscall": children[0],
        }

    # -------------------------
    # Arguments / structures
    # -------------------------
    def braced(self, children):
        # { struct_fields }
        # children[0] is struct_fields (list) after transform
        return {
            "type": "braced",
            "value": children[0],
        }

    def bracketed(self, children):
        # [ syscall_args ]
        return {
            "type": "bracketed",
            "value": children[0],
        }

    # struct_fields : struct_field? ("," _SP? struct_field)*
    def struct_fields(self, children):
        # list of already-transformed struct_field
        return children

    # key_value : NAME _SP? "=" _SP? syscall_arg -> kv
    # so the rule name is "kv", not "key_value"
    def kv(self, children):
        key, value = children
        return {
            "type": "key_value",
            "key": str(key),
            "value": value,
        }

    # function_like : NAME "(" syscall_args ")"
    def function_like(self, children):
        name, args = children
        return {
            "type": "function",
            "name": str(name),
            "args": args,
        }

    # sigset : NEGATED? "[" SIGNAL? (_SP SIGNAL)* "]"
    def sigset(self, children):
        negated = False
        args = []

        for ch in children:
            if isinstance(ch, Token) and ch.type == "NEGATED":
                negated = True
            else:
                # include SIGNAL tokens etc.
                args.append(str(ch))

        return {
            "type": "sigset",
            "negated": negated,
            "args": args,
        }

    # -------------------------
    # Expression-like args
    # -------------------------
    # c_expr : /[^,}\]\[\{}]+/
    def c_expr(self, children):
        return str(children[0])

    # plain_arg : /[^,)}\]\[{}]+/
    def plain_arg(self, children):
        return str(children[0])

    # -------------------------
    # Alert
    # -------------------------
    def alert_body(self, children):
        # whole alert line as one string is fine
        return {
            "type": "alert",
            "result": " ".join(str(c) for c in children),
        }

    # -------------------------
    # Misc helpers that still match rules
    # -------------------------
    body = first_child()
    timestamp = convert(float)


def to_json(tree: Tree) -> Any:
    return JsonTransformer().transform(tree)
