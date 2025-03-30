import logging
from pathlib import Path


logger = logging.getLogger("django")


def save_text_to_file(path: Path, content: str, encoding: str = ""):
    """
    Saves the given text content to files in the specified directory.

    Parameters:
        path (Path): The path to the directory where files will be saved.
        content (str): A dictionary where keys are filenames and values are the text to save.
        encoding (str): Encoding library to use when saving file.
    """
    if not path.parent.exists():
        path.parent.mkdir(parents=True)
        logger.debug(f"The directory {str(path)} was created.")

    with path.open("w", encoding=encoding) as file:
        file.write(content)


def delete_files_in_directory(path: Path):
    """
    Deletes all files in the specified directory.

    Parameters:
        directory_path (str): The path to the directory whose files are to be deleted.
    """
    if not path.exists() or not path.is_dir():
        logger.debug(f"The directory {str(path)} does not exist or is not a directory.")
        return

    for file in path.glob("*"):
        if file.is_file():
            file.unlink()
            logger.debug(f"Deleted: {file}")
