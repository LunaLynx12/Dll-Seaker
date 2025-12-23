"""
Configuration Manager - Manage configuration files
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional
from constants import DEFAULT_CONFIG

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class ConfigManager:
    """Manage configuration for DLL Seeker"""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize config manager"""
        self.config_path = Path(config_path) if config_path else None
        self.config = DEFAULT_CONFIG.copy()
        
        if self.config_path and self.config_path.exists():
            self.load_config()
        else:
            self._set_defaults()
    
    def load_config(self):
        """Load configuration from file"""
        if not self.config_path or not self.config_path.exists():
            return
        
        try:
            if (self.config_path.suffix.lower() == '.yaml' or self.config_path.suffix.lower() == '.yml'):
                if YAML_AVAILABLE:
                    with open(self.config_path, 'r', encoding='utf-8') as f:
                        self.config.update(yaml.safe_load(f) or {})
                else:
                    raise ImportError("PyYAML not installed. Install with: pip install pyyaml")
            else:
                # Default to JSON
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    self.config.update(json.load(f))
        except Exception:
            # If loading fails, use defaults
            self._set_defaults()
    
    def save_config(self, output_path: Optional[str] = None):
        """Save configuration to file"""
        output = Path(output_path) if output_path else self.config_path
        if not output:
            return
        
        try:
            if output.suffix.lower() == '.yaml' or output.suffix.lower() == '.yml':
                if YAML_AVAILABLE:
                    with open(output, 'w', encoding='utf-8') as f:
                        yaml.dump(self.config, f, default_flow_style=False)
                else:
                    raise ImportError("PyYAML not installed. Install with: pip install pyyaml")
            else:
                with open(output, 'w', encoding='utf-8') as f:
                    json.dump(self.config, f, indent=2)
        except Exception:
            pass
    
    def _set_defaults(self):
        """Set default configuration"""
        self.config = {
            'max_string_length': 1000,
            'min_string_length': 4,
            'max_dependency_depth': 5,
            'enable_caching': True,
            'chunk_size': 8192,
            'entropy_threshold': 7.0,
            'risk_score_threshold': 30,
            'enable_profiling': False,
            'output_format': 'json',
            'string_categorization': True,
            'malware_detection': True,
            'show_progress': True
        }
        self.config.update(DEFAULT_CONFIG)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any):
        """Set configuration value"""
        self.config[key] = value
    
    def get_all(self) -> Dict[str, Any]:
        """Get all configuration"""
        return self.config.copy()

