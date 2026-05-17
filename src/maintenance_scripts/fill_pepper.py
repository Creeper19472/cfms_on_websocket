#!/usr/bin/env python3
"""
fill_pepper.py - CFMS maintenance script

Automatically generates and fills in the `pepper` field in the [security] section
of the `config.toml` file, if it is currently empty or not present.

Usage:
    python maintenance_scripts/fill_pepper.py

This script must be run from the `src/` directory (same working directory as
`main.py`) so that `config.toml` is resolved correctly.
"""

import os
import secrets
import sys
from typing import cast

try:
    import tomlkit
except ImportError:
    print(
        "Error: 'tomlkit' package is not installed.\n"
        "Please install it using 'pip install tomlkit' or ensure you are in the correct virtual environment.",
        file=sys.stderr,
    )
    sys.exit(1)


def main() -> None:
    # Ensure the script is run from the src/ directory or it can find config.toml
    config_path = "config.toml"

    if not os.path.exists(config_path):
        print(
            "Error: 'config.toml' not found in the current directory.\n"
            "Please run this script from the 'src/' directory.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            doc = tomlkit.load(f)
    except Exception as e:
        print(f"Error reading {config_path}: {e}", file=sys.stderr)
        sys.exit(1)

    # Ensure [security] section exists
    if "security" not in doc:
        print(f"Adding [security] section to {config_path}")
        doc.add("security", tomlkit.table())

    security_section = cast(dict, doc["security"])

    # Check if pepper exists and has a value
    if "pepper" not in security_section or not security_section["pepper"]:
        # Generate a 32-byte cryptographically secure random string in hex format
        new_pepper = secrets.token_hex(32)
        security_section["pepper"] = new_pepper

        try:
            with open(config_path, "w", encoding="utf-8") as f:
                tomlkit.dump(doc, f)
            print(f"Successfully generated and filled 'pepper' in {config_path}")
        except Exception as e:
            print(f"Error writing to {config_path}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"The 'pepper' field is already set in {config_path}.")


if __name__ == "__main__":
    main()
