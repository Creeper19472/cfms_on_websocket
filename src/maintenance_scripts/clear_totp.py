#!/usr/bin/env python3
"""
clear_totp.py - CFMS maintenance script

Clears the TOTP (Two-Factor Authentication) state for users in the database.

Usage:
    # Clear for all users:
    python clear_totp.py --all

    # Or, clear for a specific user:
    python clear_totp.py <username>

This script must be run from the `src/` directory (same working directory as
`main.py`) so that `config.toml` and the database path are resolved
correctly.
"""

import argparse
import os
import sys

parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Clear TOTP state for CFMS users from the command line."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "username", nargs="?", help="Username whose TOTP state should be cleared"
    )
    group.add_argument(
        "--all",
        action="store_true",
        help="Clear TOTP state for ALL users in the database",
    )
    args = parser.parse_args()

    # Validate that the caller is running from the src/ directory so that
    # conf_loader and the database can be found.
    if not os.path.exists("config.toml"):
        print(
            "Error: 'config.toml' not found in the current directory.\n"
            "Please run this script from the 'src/' directory.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Late imports so that the path check above can produce a clean error before
    # the import machinery tries to load config.toml.
    from include.database.handler import Session  # noqa: F401
    from include.database.models.classic import User  # noqa: F401
    from include.database.models.entity import (  # noqa: F401
        Document,
        DocumentRevision,
        Folder,
    )
    from include.database.models.file import File, FileTask  # noqa: F401
    from include.database.models.keyring import UserKey  # noqa: F401

    with Session() as session:
        if args.all:
            # Clear for all users
            updated_count = session.query(User).update(
                {
                    User.totp_enabled: False,
                    User.totp_secret: None,
                    User.totp_backup_codes: None,
                }
            )
            session.commit()
            print(f"Successfully cleared TOTP state for all {updated_count} user(s).")
        else:
            # Clear for a specific user
            username = args.username
            user = session.get(User, username)
            if user is None:
                print(f"Error: User '{username}' not found.", file=sys.stderr)
                sys.exit(1)

            user.totp_enabled = False
            user.totp_secret = None
            user.totp_backup_codes = None
            session.add(user)
            session.commit()
            print(f"Successfully cleared TOTP state for user '{username}'.")


if __name__ == "__main__":
    main()
