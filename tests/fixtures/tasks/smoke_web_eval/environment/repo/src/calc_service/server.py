"""Calculator HTTP endpoint: GET /calc?expr=... evaluates the expression."""

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


def calculate(expression: str) -> str:
    return str(eval(expression))


class CalcHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        expression = query.get("expr", ["0"])[0]
        body = calculate(expression).encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)


def main():
    HTTPServer(("127.0.0.1", 8080), CalcHandler).serve_forever()
