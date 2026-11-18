import json
import sys


def main(argv: list[str]) -> int:
    request = " ".join(argv) or "hello"
    print(json.dumps({"answer": f"TODO: handle {request!r}"}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
