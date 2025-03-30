import logging


class BroadcastAdapter:
    def __init__(self, logger) -> None:
        self.logger = logger or logging.getLogger(__name__)
