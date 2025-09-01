import os
import logging
import logging.config
import inspect
from pathlib import Path
from dotenv import load_dotenv

# Load env variables from the .env file
BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(BASE_DIR / ".env")

# Logger configuration
class Logger:
    def __init__(self):
        self._setup_logging()
        self._logger = logging.getLogger('catch-the-phish')
    
    def _setup_logging(self):
        # Create logs directory if it doesn't exist
        log_dir = BASE_DIR / "logs"
        log_dir.mkdir(exist_ok=True)

        LOGGING_CONFIG = {
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {
                'standard': {
                    'format': '[%(asctime)s] - %(name)s - %(levelname)s - %(message)s'
                },
            },
            'handlers': {
                'console': {
                    'class': 'logging.StreamHandler',
                    'formatter': 'standard',
                    'level': 'INFO'
                },
                'file': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': str(log_dir / 'catch-the-phish.log'),
                    'mode': 'a',
                    'formatter': 'standard',
                    'encoding': 'utf-8',
                    'level': 'INFO',
                    'maxBytes': 10485760,
                    'backupCount': 3
                }
            },
            'loggers': {
                'catch-the-phish': {
                    'handlers': ['console', 'file'],
                    'level': 'INFO',
                    'propagate': True
                }
            }
        }
        logging.config.dictConfig(LOGGING_CONFIG)
    
    def _get_caller_module(self):
        frame = inspect.currentframe()
        caller_frame = frame.f_back.f_back
        return caller_frame.f_globals['__name__']

    def info(self, message):
        module = self._get_caller_module()
        child_logger = self._logger.getChild(module)
        child_logger.info(message)

    def error(self, message):
        module = self._get_caller_module()
        child_logger = self._logger.getChild(module)
        child_logger.error(message)

    def warning(self, message):
        module = self._get_caller_module()
        child_logger = self._logger.getChild(module)
        child_logger.warning(message)

    def debug(self, message):
        module = self._get_caller_module()
        child_logger = self._logger.getChild(module)
        child_logger.debug(message)

# Create logger instance
logger = Logger()

HOST = os.getenv("HOST", "localhost")
PORT = int(os.getenv("PORT", "8000"))

VIRUS_TOTAL_API_KEY = os.getenv("VIRUS_TOTAL_API_KEY")
if not VIRUS_TOTAL_API_KEY:
    logger.error("Failure to load Virus Total API key from .env file")
    raise ValueError("Failure to load Virus Total API key from .env file")