"""Sphinx configuration for async-hvac."""

from pathlib import Path

project = "async-hvac"
author = "async-hvac contributors"
release = (Path(__file__).resolve().parents[1] / "VERSION").read_text().strip()

extensions = ["myst_parser"]
exclude_patterns = ["_build"]
html_theme = "sphinx_rtd_theme"
