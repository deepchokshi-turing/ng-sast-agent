"""A stand-in for the model: picks a tool and its argument from the question."""


def choose_tool(question: str) -> tuple[str, str]:
    words = question.strip().split()
    if words and words[0].lower() == "count":
        return "word_count", " ".join(words[1:])
    return "find_note", " ".join(words[1:]) if len(words) > 1 else ""
