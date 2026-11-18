"""IOC extraction agent for Google SecOps (Google ADK).

`adk web` / `adk run` import this package and read `agent.root_agent`.
"""

from pathlib import Path

from dotenv import load_dotenv

# Variables already set in the environment win: python-dotenv never overwrites them.
load_dotenv(Path(__file__).parent / ".env")

from . import agent  # noqa: E402 - after the .env is loaded

__all__ = ["agent"]
