"""paths.py — Project path resolution for SocialBlobs."""

from pathlib import Path

# Project root is the parent of src/
ROOT = Path(__file__).resolve().parent.parent

CONTRACTS_DIR = ROOT / "contracts"
DATA_DIR = ROOT / "data"
CORPUS_PATH = DATA_DIR / "corpus.txt"


def contract_source(name: str) -> str:
    """Read a Vyper contract source from contracts/."""
    return (CONTRACTS_DIR / name).read_text()
