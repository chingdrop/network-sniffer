import logging
import colorlog
from pathlib import Path

from network_sniffer.files_and_storage import create_directory, create_file


def setup_logger(
    name: str, level: str = "warning", file: bool = False
) -> logging.Logger:

    log_level = {
        "critical": logging.CRITICAL,
        "error": logging.ERROR,
        "warning": logging.WARNING,
        "info": logging.INFO,
        "debug": logging.DEBUG,
    }
    logger = logging.getLogger(name)
    if logger.hasHandlers():
        return logger
    logger.setLevel(log_level[level])

    if file:
        logs_dir = Path.cwd() / "logs"
        logs_file = logs_dir / f"{name}_logfile.log"
        if not logs_dir.exists():
            create_directory(logs_dir)
        if not logs_file.exists():
            create_file(logs_file)
        file_handler = logging.FileHandler(logs_file)
        file_handler.setLevel(log_level[level])
        logger.addHandler(file_handler)

    stream_handler = colorlog.StreamHandler()
    stream_handler.setLevel(log_level[level])
    formatter = colorlog.ColoredFormatter(
        "%(log_color)s[%(asctime)s - %(levelname)s/%(name)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        log_colors={
            "DEBUG": "blue",
            "INFO": "green",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "magenta",
        },
    )
    file_handler.setFormatter(
        logging.Formatter("[%(asctime)s - %(levelname)s/%(name)s]: %(message)s")
    )
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    return logger
