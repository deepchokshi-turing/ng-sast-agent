"""CLI entrypoint: python -m support_copilot <user_id> "<message>" """

import json
import sys

from .agent import handle_request
from .users import load_user


def main() -> None:
    user = load_user(sys.argv[1])
    print(json.dumps(handle_request(user, sys.argv[2]), indent=2))


if __name__ == "__main__":
    main()
