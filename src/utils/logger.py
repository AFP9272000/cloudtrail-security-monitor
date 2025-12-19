"""
Logger Utility - Sets up structured logging
"""

import os
import sys
import logging
from datetime import datetime
from pythonjsonlogger import jsonlogger


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter for structured logging"""
    
    def add_fields(self, log_record, record, message_dict):
        """Add custom fields to log record"""
        super(CustomJsonFormatter, self).add_fields(log_record, record, message_dict)
        
        # Add timestamp
        log_record['timestamp'] = datetime.utcnow().isoformat() + 'Z'
        
        # Add log level
        log_record['level'] = record.levelname
        
        # Add source information
        log_record['logger'] = record.name
        log_record['function'] = record.funcName
        log_record['line'] = record.lineno
        
        # Add application context
        log_record['application'] = 'cloudtrail-monitor'
        log_record['environment'] = os.getenv('ENVIRONMENT', 'development')


def setup_logger(name: str, log_level: str = None) -> logging.Logger:
    """Set up structured logger
    
    Args:
        name: Logger name
        log_level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        
    Returns:
        Configured logger instance
    """
    # Get log level from environment or parameter
    if log_level is None:
        log_level = os.getenv('LOG_LEVEL', 'INFO')
    
    # Get log format preference
    log_format = os.getenv('LOG_FORMAT', 'json').lower()
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Remove existing handlers
    logger.handlers = []
    
    # Create console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(getattr(logging, log_level.upper()))
    
    # Set formatter based on preference
    if log_format == 'json':
        # JSON formatter for production
        formatter = CustomJsonFormatter(
            '%(timestamp)s %(level)s %(name)s %(message)s'
        )
    else:
        # Human-readable formatter for development
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    # Prevent propagation to root logger
    logger.propagate = False
    
    return logger


class StructuredLogger:
    """Wrapper for structured logging with additional context"""
    
    def __init__(self, logger: logging.Logger):
        """Initialize structured logger
        
        Args:
            logger: Base logger instance
        """
        self.logger = logger
        self.context = {}
    
    def add_context(self, **kwargs):
        """Add context fields to all log messages
        
        Args:
            **kwargs: Context key-value pairs
        """
        self.context.update(kwargs)
    
    def remove_context(self, *keys):
        """Remove context fields
        
        Args:
            *keys: Context keys to remove
        """
        for key in keys:
            self.context.pop(key, None)
    
    def clear_context(self):
        """Clear all context fields"""
        self.context.clear()
    
    def _log_with_context(self, level: str, message: str, **kwargs):
        """Log message with context
        
        Args:
            level: Log level
            message: Log message
            **kwargs: Additional fields
        """
        # Merge context with additional fields
        log_data = {**self.context, **kwargs}
        
        # Get logging method
        log_method = getattr(self.logger, level.lower())
        
        # Log with extra fields
        log_method(message, extra=log_data)
    
    def debug(self, message: str, **kwargs):
        """Log debug message"""
        self._log_with_context('DEBUG', message, **kwargs)
    
    def info(self, message: str, **kwargs):
        """Log info message"""
        self._log_with_context('INFO', message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message"""
        self._log_with_context('WARNING', message, **kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message"""
        self._log_with_context('ERROR', message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        """Log critical message"""
        self._log_with_context('CRITICAL', message, **kwargs)


# Suppress noisy AWS SDK logging
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)