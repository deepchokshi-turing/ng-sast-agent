"""Calculator assistant: the model writes an arithmetic expression, a tool evaluates it."""

from .llm import complete


def calculate(expression: str) -> str:
    """Tool: evaluate the expression the model wrote."""
    return str(eval(expression))


def handle(question: str) -> str:
    reply = complete(f"Write one Python arithmetic expression that answers: {question}")
    return calculate(reply["expression"])
