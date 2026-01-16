# utils/safe_eval.py
from __future__ import annotations
import ast
from typing import Any, Dict

_ALLOWED_NODES = (
    ast.Expression,
    ast.BoolOp, ast.BinOp, ast.UnaryOp, ast.Compare,
    ast.Name, ast.Load, ast.Constant,
    ast.And, ast.Or,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod,
    ast.Not,
    ast.Gt, ast.GtE, ast.Lt, ast.LtE, ast.Eq, ast.NotEq,
)

def safe_eval_bool(expr: str, ctx: Dict[str, Any]) -> bool:
    if not expr or not isinstance(expr, str):
        return False

    tree = ast.parse(expr, mode="eval")

    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_NODES):
            raise ValueError(f"Unsafe expression node: {type(node).__name__}")

        # Only allow known variable names
        if isinstance(node, ast.Name) and node.id not in ctx:
            raise ValueError(f"Unknown variable: {node.id}")

    code = compile(tree, "<safe_eval>", "eval")
    return bool(eval(code, {"__builtins__": {}}, ctx))