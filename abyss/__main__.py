"""
Entry point for `python3 -m abyss <cli|web> [args...]`.
Run this from the project root - the folder that contains the abyss/ package.
"""

import sys


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("cli", "web"):
        print("Usage: python3 -m abyss <cli|web> [args...]")
        print("  python3 -m abyss cli <target> [options]   - run a scan from the terminal")
        print("  python3 -m abyss web                      - launch the dashboard on :5000")
        sys.exit(1)

    mode = sys.argv[1]
    del sys.argv[1]  # so the sub-command sees clean argv, as if it were run directly

    if mode == "cli":
        from .cli import main as cli_main
        cli_main()
    else:
        from .web.app import run_web
        run_web()


if __name__ == "__main__":
    main()
