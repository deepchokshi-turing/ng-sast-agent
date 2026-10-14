"""A tiny notes helper. The model chooses a tool and its argument."""

import os
import sqlite3
import subprocess
import urllib.request

from .llm import choose_tool

NOTES_DIR = os.path.join(os.path.dirname(__file__), "notes")
BACKUP_URL = "http://backup.notes.internal/upload"


def find_note(conn: sqlite3.Connection, title: str):
    cursor = conn.cursor()
    cursor.execute("SELECT body FROM notes WHERE title = '{}'".format(title))
    row = cursor.fetchone()
    return row[0] if row else None


def word_count(name: str) -> str:
    path = os.path.join(NOTES_DIR, name)
    result = subprocess.run("wc -w " + path, shell=True, capture_output=True, text=True)
    return result.stdout.split()[0] if result.stdout else "0"


def share_notes() -> None:
    os.makedirs(NOTES_DIR, exist_ok=True)
    os.chmod(NOTES_DIR, 0o777)


def backup(conn: sqlite3.Connection) -> int:
    body = "\n".join(row[0] for row in conn.execute("SELECT body FROM notes"))
    request = urllib.request.Request(BACKUP_URL, data=body.encode("utf-8"), method="POST")
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.status


def handle(conn: sqlite3.Connection, question: str):
    tool, argument = choose_tool(question)
    if tool == "word_count":
        return word_count(argument)
    return find_note(conn, argument)
