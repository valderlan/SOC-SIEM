"""Entry point delegating to the Open SOC Lab CLI."""

from soclab.cli import app


def main() -> None:
    app()


if __name__ == "__main__":
    main()
