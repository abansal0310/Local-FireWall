import os
import json
from pathlib import Path

class Config:
    """Centralized configuration management"""
    
    def __init__(self):
        self.BASE_DIR = Path(__file__).parent.parent
        self.load_config()
    
    def load_config(self):
        """Load configuration from environment and defaults"""
        # Network Configuration
        self.NETWORK_INTERFACE = os.getenv('NETWORK_INTERFACE', 'en0')  # Changed from eth0 to en0 for macOS
        self.MONITOR_ALL_INTERFACES = os.getenv('MONITOR_ALL_INTERFACES', 'True') == 'True'
        
        # Monitoring Thresholds
        self.PORT_SCAN_THRESHOLD = int(os.getenv('PORT_SCAN_THRESHOLD', '10'))
        self.PORT_SCAN_TIME_WINDOW = int(os.getenv('PORT_SCAN_TIME_WINDOW', '60'))
        self.FLOOD_THRESHOLD = int(os.getenv('FLOOD_THRESHOLD', '100'))
        self.FLOOD_TIME_WINDOW = int(os.getenv('FLOOD_TIME_WINDOW', '10'))
        self.BRUTE_FORCE_THRESHOLD = int(os.getenv('BRUTE_FORCE_THRESHOLD', '5'))
        self.BRUTE_FORCE_TIME_WINDOW = int(os.getenv('BRUTE_FORCE_TIME_WINDOW', '300'))
        
        # File Paths
        self.LOG_DIR = self.BASE_DIR / 'logs'
        self.DATA_DIR = self.BASE_DIR / 'data'
        self.RULES_FILE = self.BASE_DIR / 'config' / 'rules.json'
        
        # Logging Configuration
        self.LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
        self.MAX_LOG_SIZE = int(os.getenv('MAX_LOG_SIZE', '10485760'))  # 10MB
        self.LOG_BACKUP_COUNT = int(os.getenv('LOG_BACKUP_COUNT', '5'))
        
        # Alert Configuration
        self.ENABLE_EMAIL_ALERTS = os.getenv('ENABLE_EMAIL_ALERTS', 'False') == 'True'
        self.EMAIL_SMTP_SERVER = os.getenv('EMAIL_SMTP_SERVER', 'smtp.gmail.com')
        self.EMAIL_SMTP_PORT = int(os.getenv('EMAIL_SMTP_PORT', '587'))
        self.EMAIL_FROM = os.getenv('EMAIL_FROM', '')
        self.EMAIL_TO = os.getenv('EMAIL_TO', '')
        self.EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD', '')
        
        # Create directories if they don't exist
        self.LOG_DIR.mkdir(exist_ok=True)
        self.DATA_DIR.mkdir(exist_ok=True)
    
    def get_rules(self):
        """Load firewall and IDS rules from JSON file"""
        try:
            with open(self.RULES_FILE, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Rules file not found: {self.RULES_FILE}")
            return {"firewall_rules": [], "ids_rules": []}
        except json.JSONDecodeError as e:
            print(f"Error parsing rules file: {e}")
            return {"firewall_rules": [], "ids_rules": []}
    
    def save_rules(self, rules):
        """Save rules to JSON file"""
        try:
            with open(self.RULES_FILE, 'w') as f:
                json.dump(rules, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving rules: {e}")
            return False

# Global config instance
config = Config()