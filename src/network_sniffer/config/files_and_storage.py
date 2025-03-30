import logging
from pathlib import Path


logger = logging.getLogger("django")


def create_directory(path: Path | str) -> None:
    """Create a directory from a string or a Path object.

    Args:
        path (Path, str): Directory path
    """
    if isinstance(path, str):
        path = Path(path)
    path.mkdir(parents=True, exist_ok=True)


def create_file(path: Path | str) -> None:
    if isinstance(path, str):
        path = Path(path)
    path.touch()
