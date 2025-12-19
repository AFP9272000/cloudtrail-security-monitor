"""
Config Loader - Loads and validates configuration
"""

import os
import yaml
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional


class ConfigLoader:
    """Loads and manages configuration"""
    
    DEFAULT_CONFIG = {
        'monitoring': {
            'lookback_minutes': 15,
            'batch_size': 50,
            'max_events_per_run': 1000
        },
        'alerts': {
            'cooldown_minutes': 60,
            'batch_threshold': 5,
            'enable_slack': False,
            'enable_email': True
        },
        'security': {
            'track_failed_logins': True,
            'failed_login_threshold': 3,
            'failed_login_window_minutes': 10,
            'detect_privilege_escalation': True,
            'detect_data_exfiltration': True
        },
        'performance': {
            'enable_caching': True,
            'cache_ttl_seconds': 300,
            'max_concurrent_requests': 10
        },
        'logging': {
            'level': 'INFO',
            'format': 'json',
            'enable_cloudwatch': False
        }
    }
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize config loader
        
        Args:
            config_path: Path to configuration file
        """
        self.logger = logging.getLogger(__name__)
        self.config = self.DEFAULT_CONFIG.copy()
        
        # Load configuration file if provided
        if config_path and os.path.exists(config_path):
            self._load_config_file(config_path)
        else:
            self.logger.info("Using default configuration")
        
        # Override with environment variables
        self._load_env_overrides()
        
        # Validate configuration
        self._validate_config()
    
    def _load_config_file(self, config_path: str) -> None:
        """Load configuration from YAML file
        
        Args:
            config_path: Path to config file
        """
        try:
            self.logger.info(f"Loading configuration from {config_path}")
            
            with open(config_path, 'r') as f:
                file_config = yaml.safe_load(f)
            
            # Merge with default config
            self._deep_merge(self.config, file_config)
            
            self.logger.info("Configuration loaded successfully")
            
        except FileNotFoundError:
            self.logger.warning(f"Config file not found: {config_path}")
        except yaml.YAMLError as e:
            self.logger.error(f"Error parsing YAML config: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Error loading config: {e}")
            raise
    
    def _load_env_overrides(self) -> None:
        """Load configuration overrides from environment variables"""
        # Monitoring overrides
        if os.getenv('LOOKBACK_MINUTES'):
            self.config['monitoring']['lookback_minutes'] = int(os.getenv('LOOKBACK_MINUTES'))
        
        # Alert overrides
        if os.getenv('ALERT_COOLDOWN_MINUTES'):
            self.config['alerts']['cooldown_minutes'] = int(os.getenv('ALERT_COOLDOWN_MINUTES'))
        
        if os.getenv('ENABLE_SLACK'):
            self.config['alerts']['enable_slack'] = os.getenv('ENABLE_SLACK').lower() == 'true'
        
        # Logging overrides
        if os.getenv('LOG_LEVEL'):
            self.config['logging']['level'] = os.getenv('LOG_LEVEL')
        
        if os.getenv('LOG_FORMAT'):
            self.config['logging']['format'] = os.getenv('LOG_FORMAT')
        
        self.logger.debug("Environment variable overrides applied")
    
    def _deep_merge(self, base: Dict, override: Dict) -> None:
        """Deep merge two dictionaries
        
        Args:
            base: Base dictionary (modified in place)
            override: Override dictionary
        """
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def _validate_config(self) -> None:
        """Validate configuration values"""
        # Validate lookback minutes
        lookback = self.config['monitoring']['lookback_minutes']
        if lookback < 1 or lookback > 1440:  # Max 24 hours
            raise ValueError(f"Invalid lookback_minutes: {lookback}. Must be between 1 and 1440")
        
        # Validate cooldown minutes
        cooldown = self.config['alerts']['cooldown_minutes']
        if cooldown < 0:
            raise ValueError(f"Invalid cooldown_minutes: {cooldown}. Must be non-negative")
        
        # Validate log level
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        log_level = self.config['logging']['level'].upper()
        if log_level not in valid_levels:
            raise ValueError(f"Invalid log level: {log_level}. Must be one of {valid_levels}")
        
        self.logger.debug("Configuration validation passed")
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """Get configuration value by dot-notation path
        
        Args:
            key_path: Dot-notation path (e.g., 'monitoring.lookback_minutes')
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        keys = key_path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def set(self, key_path: str, value: Any) -> None:
        """Set configuration value by dot-notation path
        
        Args:
            key_path: Dot-notation path
            value: Value to set
        """
        keys = key_path.split('.')
        config = self.config
        
        # Navigate to parent dictionary
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        # Set the value
        config[keys[-1]] = value
    
    def to_dict(self) -> Dict[str, Any]:
        """Get full configuration as dictionary
        
        Returns:
            Configuration dictionary
        """
        return self.config.copy()
    
    def to_json(self) -> str:
        """Get configuration as JSON string
        
        Returns:
            JSON string
        """
        return json.dumps(self.config, indent=2)
    
    def save_to_file(self, file_path: str) -> None:
        """Save current configuration to file
        
        Args:
            file_path: Path to save config
        """
        try:
            with open(file_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
            
            self.logger.info(f"Configuration saved to {file_path}")
            
        except Exception as e:
            self.logger.error(f"Error saving config: {e}")
            raise