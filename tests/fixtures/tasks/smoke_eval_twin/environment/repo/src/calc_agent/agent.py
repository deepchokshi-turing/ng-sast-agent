"""Calculator assistant: the model writes an arithmetic expression, a tool evaluates it.

The tool parses the expression and evaluates arithmetic nodes only, so the model
cannot make it run anything else.
"""

import ast
import operator

from .llm import complete

_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.USub: operator.neg,
}


def _evaluate(node: ast.AST) -> float:
    if isinstance(node, ast.Expression):
        return _evaluate(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPERATORS:
        return _OPERATORS[type(node.op)](_evaluate(node.left), _evaluate(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPERATORS:
        return _OPERATORS[type(node.op)](_evaluate(node.operand))
    raise ValueError("only arithmetic is allowed")


def calculate(expression: str) -> str:
    """Tool: evaluate the arithmetic expression the model wrote."""
    value = _evaluate(ast.parse(expression, mode="eval"))
    return str(int(value)) if float(value).is_integer() else str(value)


def handle(question: str) -> str:
    reply = complete(f"Write one Python arithmetic expression that answers: {question}")
    return calculate(reply["expression"])
