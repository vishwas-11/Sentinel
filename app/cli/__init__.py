"""Sentinel CLI package."""

from app.cli.main import main
from app.cli.parser import create_parser

__all__ = ["create_parser", "main"]
