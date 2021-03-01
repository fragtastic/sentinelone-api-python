import logging
from .client import Client

logger = logging.getLogger(__name__)
logger.setLevel(logging.NOTSET)
logger.addHandler(logging.NullHandler())
