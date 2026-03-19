"""Example secure LLM application - demonstrates safe patterns.

This file shows how to fix each vulnerability pattern.
Run `llm-seclint scan examples/secure_app.py` to verify no issues are found.
"""

import json
import os
import sqlite3
import subprocess
from pathlib import Path

import openai

# LS001 fix: Use environment variables
openai.api_key = os.environ["OPENAI_API_KEY"]


def get_chat_response(user_input: str) -> str:
    """Get a response from the LLM with proper input separation."""
    # LS002 fix: Separate system prompt from user input via message roles
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": user_input},
        ],
    )
    return response.choices[0].message.content


def search_database(search_term: str) -> list:
    """Search database using parameterized queries."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # LS003 fix: Use parameterized query
    cursor.execute(
        "SELECT * FROM products WHERE name LIKE ?",
        (f"%{search_term}%",),
    )
    return cursor.fetchall()


# Allowlist of permitted commands
ALLOWED_COMMANDS = {"ls", "date", "whoami", "df"}


def execute_command(command_name: str) -> str:
    """Execute only pre-approved commands."""
    # LS004 fix: Validate against allowlist, use argument list (no shell=True)
    if command_name not in ALLOWED_COMMANDS:
        raise ValueError(f"Command not allowed: {command_name}")

    result = subprocess.run(
        [command_name], capture_output=True, text=True, check=False
    )
    return result.stdout


# Allowed base directory for file access
ALLOWED_BASE = Path("/app/data").resolve()


def read_file(filename: str) -> str:
    """Read a file with path traversal protection."""
    # LS005 fix: Resolve path and verify it's within allowed directory
    target = (ALLOWED_BASE / filename).resolve()
    if not str(target).startswith(str(ALLOWED_BASE)):
        raise ValueError(f"Path traversal detected: {filename}")

    with open(str(target)) as f:
        return f.read()


def parse_response(llm_response: str) -> dict:
    """Parse structured data safely."""
    # LS006 fix: Use json.loads instead of eval
    return json.loads(llm_response)


def main() -> None:
    user_msg = input("Enter your message: ")
    response = get_chat_response(user_msg)
    print(f"LLM says: {response}")


if __name__ == "__main__":
    main()
