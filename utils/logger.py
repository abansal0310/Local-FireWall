import logging
import logging.handlers
import sys
from pathlib import Path
from datetime import datetime
from colorama import Fore, Back, Style, init
from config.settings import config

# Initialize colorama
init(autoreset=True)

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for console output"""
    
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{log_color}{record.levelname}{Style.RESET_ALL}"
        return super().format(record)

class SecurityLogger:
    """Centralized logging system for the firewall/IDS"""
    
    def __init__(self, name="FirewallIDS"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, config.LOG_LEVEL))
        
        # Prevent duplicate handlers
        if self.logger.handlers:
            return
            
        self.setup_handlers()
    
    def setup_handlers(self):
        """Setup file and console handlers"""
        
        # Console Handler with colors
        console_handler = logging.StreamHandler(sys.stdout)
        console_formatter = ColoredFormatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # Main log file handler with rotation
        main_log_file = config.LOG_DIR / 'firewall_ids.log'
        file_handler = logging.handlers.RotatingFileHandler(
            main_log_file,
            maxBytes=config.MAX_LOG_SIZE,
            backupCount=config.LOG_BACKUP_COUNT
        )
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        
        # Security events log (separate file)
        security_log_file = config.LOG_DIR / 'security_events.log'
        security_handler = logging.handlers.RotatingFileHandler(
            security_log_file,
            maxBytes=config.MAX_LOG_SIZE,
            backupCount=config.LOG_BACKUP_COUNT
        )
        security_formatter = logging.Formatter(
            '%(asctime)s - SECURITY - %(levelname)s - %(message)s'
        )
        security_handler.setFormatter(security_formatter)
        security_handler.addFilter(lambda record: hasattr(record, 'security_event'))
        self.logger.addHandler(security_handler)
    
    def info(self, message):
        """Log info message"""
        self.logger.info(message)
    
    def warning(self, message):
        """Log warning message"""
        self.logger.warning(message)
    
    def error(self, message):
        """Log error message"""
        self.logger.error(message)
    
    def critical(self, message):
        """Log critical message"""
        self.logger.critical(message)
    
    def debug(self, message):
        """Log debug message"""
        self.logger.debug(message)
    
    def security_event(self, event_type, message, severity="INFO"):
        """Log security-specific events"""
        record = logging.LogRecord(
            name=self.logger.name,
            level=getattr(logging, severity),
            pathname="",
            lineno=0,
            msg=f"[{event_type}] {message}",
            args=(),
            exc_info=None
        )
        record.security_event = True
        self.logger.handle(record)

# Global logger instance
logger = SecurityLogger()

# Test function
def test_logger():
    """Test all logging levels"""
    logger.info("Logger initialized successfully")
    logger.debug("Debug message test")
    logger.warning("Warning message test")
    logger.error("Error message test")
    logger.security_event("TEST", "Security event test", "WARNING")
    print(f"Log files created in: {config.LOG_DIR}")

if __name__ == "__main__":
    test_logger()