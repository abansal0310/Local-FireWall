import subprocess
import json
import threading
import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pathlib import Path
from utils.logger import logger
from config.settings import config

class FirewallManager:
    """Advanced firewall rule management and enforcement system"""
    
    def __init__(self):
        self.active_rules = {}  # {rule_id: rule_info}
        self.rule_history = deque(maxlen=10000)
        self.blocked_ips = set()
        self.allowed_ips = set()
        self.rule_lock = threading.Lock()
        
        # Firewall chains
        self.chains = {
            'INPUT': 'Incoming traffic',
            'OUTPUT': 'Outgoing traffic', 
            'FORWARD': 'Forwarded traffic'
        }
        
        # Rule priorities
        self.rule_priorities = {
            'critical': 1,
            'high': 10,
            'medium': 100,
            'low': 1000
        }
        
        # Load existing rules
        self.load_firewall_rules()
        
        logger.info("FirewallManager initialized")
    
    def load_firewall_rules(self):
        """Load firewall rules from configuration"""
        try:
            rules = config.get_rules()
            firewall_rules = rules.get('firewall_rules', [])
            
            for rule in firewall_rules:
                if rule.get('enabled', True):
                    self._apply_rule(rule, startup=True)
            
            logger.info(f"Loaded {len(firewall_rules)} firewall rules")
            
        except Exception as e:
            logger.error(f"Error loading firewall rules: {e}")
    
    def add_rule(self, rule_config, priority='medium'):
        """Add a new firewall rule"""
        try:
            with self.rule_lock:
                rule_id = self._generate_rule_id()
                
                rule_info = {
                    'id': rule_id,
                    'config': rule_config,
                    'priority': priority,
                    'created_at': datetime.now(),
                    'active': False,
                    'iptables_rule': None
                }
                
                # Apply the rule
                success = self._apply_rule(rule_config, rule_id=rule_id)
                
                if success:
                    rule_info['active'] = True
                    self.active_rules[rule_id] = rule_info
                    
                    # Log rule addition
                    self._log_rule_action('ADD', rule_id, rule_config)
                    
                    logger.info(f"Added firewall rule {rule_id}: {rule_config.get('description', 'No description')}")
                    return rule_id
                else:
                    logger.error(f"Failed to apply firewall rule: {rule_config}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error adding firewall rule: {e}")
            return None
    
    def remove_rule(self, rule_id):
        """Remove a firewall rule"""
        try:
            with self.rule_lock:
                if rule_id not in self.active_rules:
                    logger.warning(f"Rule {rule_id} not found")
                    return False
                
                rule_info = self.active_rules[rule_id]
                success = self._remove_rule(rule_info)
                
                if success:
                    del self.active_rules[rule_id]
                    self._log_rule_action('REMOVE', rule_id, rule_info['config'])
                    logger.info(f"Removed firewall rule {rule_id}")
                    return True
                else:
                    logger.error(f"Failed to remove firewall rule {rule_id}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error removing firewall rule: {e}")
            return False
    
    def block_ip(self, ip_address, duration=None, reason="Manual block"):
        """Block an IP address"""
        try:
            if ip_address in self.blocked_ips:
                logger.info(f"IP {ip_address} already blocked")
                return True
            
            # Create iptables rule
            block_cmd = ['iptables', '-I', 'INPUT', '-s', ip_address, '-j', 'DROP']
            result = subprocess.run(block_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.blocked_ips.add(ip_address)
                
                # Create rule entry
                rule_config = {
                    'action': 'DROP',
                    'source': ip_address,
                    'description': f"Blocked IP: {reason}",
                    'temporary': duration is not None
                }
                
                rule_id = self._generate_rule_id()
                rule_info = {
                    'id': rule_id,
                    'config': rule_config,
                    'priority': 'high',
                    'created_at': datetime.now(),
                    'expires_at': datetime.now() + timedelta(seconds=duration) if duration else None,
                    'active': True,
                    'iptables_rule': block_cmd
                }
                
                self.active_rules[rule_id] = rule_info
                self._log_rule_action('BLOCK_IP', rule_id, rule_config)
                
                logger.security_event("IP_BLOCKED", 
                    f"Blocked IP {ip_address}: {reason}", 
                    "WARNING")
                
                return True
            else:
                logger.error(f"Failed to block IP {ip_address}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {e}")
            return False
    
    def unblock_ip(self, ip_address):
        """Unblock an IP address"""
        try:
            if ip_address not in self.blocked_ips:
                logger.info(f"IP {ip_address} not currently blocked")
                return True
            
            # Remove iptables rule
            unblock_cmd = ['iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP']
            result = subprocess.run(unblock_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.blocked_ips.discard(ip_address)
                
                # Remove from active rules
                for rule_id, rule_info in list(self.active_rules.items()):
                    if (rule_info['config'].get('source') == ip_address and 
                        rule_info['config'].get('action') == 'DROP'):
                        del self.active_rules[rule_id]
                        break
                
                self._log_rule_action('UNBLOCK_IP', None, {'source': ip_address})
                
                logger.security_event("IP_UNBLOCKED", 
                    f"Unblocked IP {ip_address}", 
                    "INFO")
                
                return True
            else:
                logger.error(f"Failed to unblock IP {ip_address}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error unblocking IP {ip_address}: {e}")
            return False
    
    def allow_ip(self, ip_address, reason="Manual allow"):
        """Explicitly allow an IP address"""
        try:
            if ip_address in self.allowed_ips:
                logger.info(f"IP {ip_address} already allowed")
                return True
            
            # Create iptables rule (insert at beginning)
            allow_cmd = ['iptables', '-I', 'INPUT', '1', '-s', ip_address, '-j', 'ACCEPT']
            result = subprocess.run(allow_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.allowed_ips.add(ip_address)
                
                rule_config = {
                    'action': 'ACCEPT',
                    'source': ip_address,
                    'description': f"Allowed IP: {reason}",
                    'priority': 'critical'
                }
                
                rule_id = self._generate_rule_id()
                rule_info = {
                    'id': rule_id,
                    'config': rule_config,
                    'priority': 'critical',
                    'created_at': datetime.now(),
                    'active': True,
                    'iptables_rule': allow_cmd
                }
                
                self.active_rules[rule_id] = rule_info
                self._log_rule_action('ALLOW_IP', rule_id, rule_config)
                
                logger.info(f"Allowed IP {ip_address}: {reason}")
                return True
            else:
                logger.error(f"Failed to allow IP {ip_address}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error allowing IP {ip_address}: {e}")
            return False
    
    def block_port(self, port, protocol='tcp', reason="Security block"):
        """Block a specific port"""
        try:
            block_cmd = ['iptables', '-I', 'INPUT', '-p', protocol, '--dport', str(port), '-j', 'DROP']
            result = subprocess.run(block_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                rule_config = {
                    'action': 'DROP',
                    'protocol': protocol,
                    'port': port,
                    'description': f"Blocked port {port}/{protocol}: {reason}"
                }
                
                rule_id = self._generate_rule_id()
                rule_info = {
                    'id': rule_id,
                    'config': rule_config,
                    'priority': 'high',
                    'created_at': datetime.now(),
                    'active': True,
                    'iptables_rule': block_cmd
                }
                
                self.active_rules[rule_id] = rule_info
                self._log_rule_action('BLOCK_PORT', rule_id, rule_config)
                
                logger.security_event("PORT_BLOCKED", 
                    f"Blocked port {port}/{protocol}: {reason}", 
                    "WARNING")
                
                return rule_id
            else:
                logger.error(f"Failed to block port {port}/{protocol}: {result.stderr}")
                return None
                
        except Exception as e:
            logger.error(f"Error blocking port {port}: {e}")
            return None
    
    def create_rate_limit_rule(self, source_ip, rate_limit, burst=None):
        """Create rate limiting rule for an IP"""
        try:
            if not burst:
                burst = rate_limit * 2
            
            # Create rate limiting rule
            rate_cmd = [
                'iptables', '-I', 'INPUT', '-s', source_ip,
                '-m', 'limit', '--limit', f"{rate_limit}/min",
                '--limit-burst', str(burst), '-j', 'ACCEPT'
            ]
            
            drop_cmd = ['iptables', '-I', 'INPUT', '-s', source_ip, '-j', 'DROP']
            
            # Apply both rules
            rate_result = subprocess.run(rate_cmd, capture_output=True, text=True)
            drop_result = subprocess.run(drop_cmd, capture_output=True, text=True)
            
            if rate_result.returncode == 0 and drop_result.returncode == 0:
                rule_config = {
                    'action': 'RATE_LIMIT',
                    'source': source_ip,
                    'rate_limit': rate_limit,
                    'burst': burst,
                    'description': f"Rate limited {source_ip} to {rate_limit}/min"
                }
                
                rule_id = self._generate_rule_id()
                rule_info = {
                    'id': rule_id,
                    'config': rule_config,
                    'priority': 'medium',
                    'created_at': datetime.now(),
                    'active': True,
                    'iptables_rules': [rate_cmd, drop_cmd]
                }
                
                self.active_rules[rule_id] = rule_info
                self._log_rule_action('RATE_LIMIT', rule_id, rule_config)
                
                logger.info(f"Applied rate limiting to {source_ip}: {rate_limit}/min")
                return rule_id
            else:
                logger.error(f"Failed to apply rate limiting to {source_ip}")
                return None
                
        except Exception as e:
            logger.error(f"Error creating rate limit rule: {e}")
            return None
    
    def _apply_rule(self, rule_config, rule_id=None, startup=False):
        """Apply a firewall rule to iptables"""
        try:
            action = rule_config.get('action', 'DROP')
            protocol = rule_config.get('protocol', 'tcp')
            ports = rule_config.get('ports', [])
            source = rule_config.get('source', 'any')
            destination = rule_config.get('destination', 'any')
            
            # Build iptables command
            cmd = ['iptables', '-I', 'INPUT']
            
            # Add protocol
            if protocol != 'any':
                cmd.extend(['-p', protocol])
            
            # Add source
            if source != 'any':
                cmd.extend(['-s', source])
            
            # Add destination
            if destination != 'any':
                cmd.extend(['-d', destination])
            
            # Add ports
            if ports:
                if isinstance(ports, list):
                    if len(ports) == 1:
                        cmd.extend(['--dport', str(ports[0])])
                    else:
                        port_range = f"{min(ports)}:{max(ports)}"
                        cmd.extend(['-m', 'multiport', '--dports', ','.join(map(str, ports))])
                else:
                    cmd.extend(['--dport', str(ports)])
            
            # Add action
            cmd.extend(['-j', action])
            
            # Execute command
            if not startup:  # Don't actually apply during testing
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode != 0:
                    logger.error(f"Failed to apply rule: {result.stderr}")
                    return False
            
            if rule_id and rule_id in self.active_rules:
                self.active_rules[rule_id]['iptables_rule'] = cmd
            
            return True
            
        except Exception as e:
            logger.error(f"Error applying rule: {e}")
            return False
    
    def _remove_rule(self, rule_info):
        """Remove a firewall rule from iptables"""
        try:
            iptables_rule = rule_info.get('iptables_rule')
            iptables_rules = rule_info.get('iptables_rules', [])
            
            success = True
            
            # Remove single rule
            if iptables_rule:
                # Convert INSERT to DELETE
                cmd = iptables_rule.copy()
                cmd[1] = '-D'  # Change -I to -D
                if cmd[2] in ['INPUT', 'OUTPUT', 'FORWARD']:
                    # Remove the position argument for -D
                    if len(cmd) > 3 and cmd[3].isdigit():
                        cmd.pop(3)
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    logger.warning(f"Failed to remove rule: {result.stderr}")
                    success = False
            
            # Remove multiple rules
            for rule in iptables_rules:
                cmd = rule.copy()
                cmd[1] = '-D'
                if cmd[2] in ['INPUT', 'OUTPUT', 'FORWARD']:
                    if len(cmd) > 3 and cmd[3].isdigit():
                        cmd.pop(3)
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    logger.warning(f"Failed to remove rule: {result.stderr}")
                    success = False
            
            return success
            
        except Exception as e:
            logger.error(f"Error removing rule: {e}")
            return False
    
    def cleanup_expired_rules(self):
        """Clean up expired temporary rules"""
        try:
            current_time = datetime.now()
            expired_rules = []
            
            with self.rule_lock:
                for rule_id, rule_info in self.active_rules.items():
                    expires_at = rule_info.get('expires_at')
                    if expires_at and current_time >= expires_at:
                        expired_rules.append(rule_id)
                
                for rule_id in expired_rules:
                    self.remove_rule(rule_id)
                    logger.info(f"Removed expired rule {rule_id}")
            
            return len(expired_rules)
            
        except Exception as e:
            logger.error(f"Error cleaning up expired rules: {e}")
            return 0
    
    def get_firewall_status(self):
        """Get current firewall status"""
        try:
            # Get iptables rules
            result = subprocess.run(['iptables', '-L', '-n', '--line-numbers'], 
                                  capture_output=True, text=True)
            
            status = {
                'active_rules': len(self.active_rules),
                'blocked_ips': len(self.blocked_ips),
                'allowed_ips': len(self.allowed_ips),
                'iptables_output': result.stdout if result.returncode == 0 else None,
                'last_updated': datetime.now(),
                'rules_by_priority': defaultdict(int)
            }
            
            # Count rules by priority
            for rule_info in self.active_rules.values():
                priority = rule_info.get('priority', 'medium')
                status['rules_by_priority'][priority] += 1
            
            return status
            
        except Exception as e:
            logger.error(f"Error getting firewall status: {e}")
            return {'error': str(e)}
    
    def backup_rules(self):
        """Create backup of current firewall rules"""
        try:
            backup_data = {
                'timestamp': datetime.now().isoformat(),
                'active_rules': {},
                'blocked_ips': list(self.blocked_ips),
                'allowed_ips': list(self.allowed_ips)
            }
            
            # Serialize active rules
            for rule_id, rule_info in self.active_rules.items():
                backup_data['active_rules'][rule_id] = {
                    'config': rule_info['config'],
                    'priority': rule_info['priority'],
                    'created_at': rule_info['created_at'].isoformat(),
                    'expires_at': rule_info.get('expires_at').isoformat() if rule_info.get('expires_at') else None
                }
            
            # Save to file
            backup_file = Path(__file__).parent.parent / "data" / f"firewall_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            backup_file.parent.mkdir(parents=True, exist_ok=True)
            with open(backup_file, 'w') as f:
                json.dump(backup_data, f, indent=2)
            
            logger.info(f"Firewall rules backed up to {backup_file}")
            return str(backup_file)
            
        except Exception as e:
            logger.error(f"Error backing up rules: {e}")
            return None
    
    def restore_rules(self, backup_file):
        """Restore firewall rules from backup"""
        try:
            with open(backup_file, 'r') as f:
                backup_data = json.load(f)
            
            # Clear current rules
            self.flush_rules()
            
            # Restore rules
            for rule_id, rule_data in backup_data['active_rules'].items():
                self.add_rule(rule_data['config'], rule_data['priority'])
            
            # Restore IP lists
            for ip in backup_data.get('blocked_ips', []):
                self.block_ip(ip, reason="Restored from backup")
            
            for ip in backup_data.get('allowed_ips', []):
                self.allow_ip(ip, reason="Restored from backup")
            
            logger.info(f"Firewall rules restored from {backup_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error restoring rules: {e}")
            return False
    
    def flush_rules(self):
        """Remove all custom firewall rules"""
        try:
            # Remove all custom rules
            with self.rule_lock:
                for rule_id in list(self.active_rules.keys()):
                    self.remove_rule(rule_id)
            
            # Clear IP sets
            self.blocked_ips.clear()
            self.allowed_ips.clear()
            
            logger.info("All firewall rules flushed")
            return True
            
        except Exception as e:
            logger.error(f"Error flushing rules: {e}")
            return False
    
    def _generate_rule_id(self):
        """Generate unique rule ID"""
        return f"FW_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{id(self) % 10000:04d}"
    
    def _log_rule_action(self, action, rule_id, rule_config):
        """Log firewall rule actions"""
        log_entry = {
            'timestamp': datetime.now(),
            'action': action,
            'rule_id': rule_id,
            'rule_config': rule_config
        }
        
        self.rule_history.append(log_entry)
        
        logger.security_event("FIREWALL_RULE_CHANGE", 
            f"Firewall {action}: {rule_config.get('description', 'No description')}", 
            "INFO")
    
    def get_rule_statistics(self):
        """Get firewall rule statistics"""
        recent_actions = [
            entry for entry in self.rule_history 
            if (datetime.now() - entry['timestamp']).total_seconds() < 86400  # Last 24 hours
        ]
        
        action_counts = defaultdict(int)
        for entry in recent_actions:
            action_counts[entry['action']] += 1
        
        return {
            'total_active_rules': len(self.active_rules),
            'blocked_ips': len(self.blocked_ips),
            'allowed_ips': len(self.allowed_ips),
            'recent_actions_24h': len(recent_actions),
            'action_breakdown': dict(action_counts),
            'rules_by_priority': {
                priority: len([r for r in self.active_rules.values() if r['priority'] == priority])
                for priority in self.rule_priorities.keys()
            }
        }

def test_firewall_manager():
    """Test firewall manager functionality"""
    fw = FirewallManager()
    
    print("Testing FirewallManager...")
    
    # Test blocking an IP
    result = fw.block_ip('192.168.1.100', duration=300, reason="Test block")
    print(f"Block IP result: {result}")
    
    # Test creating rate limit
    rule_id = fw.create_rate_limit_rule('192.168.1.200', 10)
    print(f"Rate limit rule ID: {rule_id}")
    
    # Test firewall status
    status = fw.get_firewall_status()
    print(f"Firewall status: {status}")
    
    # Test statistics
    stats = fw.get_rule_statistics()
    print(f"Rule statistics: {stats}")

if __name__ == "__main__":
    test_firewall_manager()
