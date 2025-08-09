import subprocess
import time
import json
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pathlib import Path
from utils.logger import logger
from config.settings import config
from utils.notifier import NotificationManager

class AutoResponseSystem:
    """Automated response system for security threats"""
    
    def __init__(self):
        self.active_blocks = {}  # {ip: block_info}
        self.response_history = deque(maxlen=10000)
        self.notification_manager = NotificationManager()
        self.blocked_ips = set()
        self.temp_blocks = {}  # {ip: expiry_time}
        self.response_rules = self._load_response_rules()
        self.lock = threading.Lock()
        
        # Response thresholds
        self.severity_thresholds = {
            'low': {'action': 'log', 'duration': 0},
            'medium': {'action': 'temp_block', 'duration': 300},  # 5 minutes
            'high': {'action': 'temp_block', 'duration': 1800},   # 30 minutes
            'critical': {'action': 'permanent_block', 'duration': 0}
        }
        
        # Cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired_blocks, daemon=True)
        self.cleanup_thread.start()
        
        logger.info("AutoResponseSystem initialized")
    
    def process_threat(self, threat_info):
        """Process detected threat and execute appropriate response"""
        try:
            threat_type = threat_info.get('type')
            severity = threat_info.get('severity', 'medium')
            src_ip = threat_info.get('src_ip')
            details = threat_info.get('details', {})
            
            if not src_ip or not threat_type:
                logger.warning("Invalid threat info provided")
                return False
            
            # Check if IP is whitelisted
            if self._is_whitelisted(src_ip):
                logger.info(f"IP {src_ip} is whitelisted, skipping response")
                return False
            
            # Determine response action
            response_action = self._determine_response_action(threat_type, severity, src_ip)
            
            # Execute response
            success = self._execute_response(response_action, src_ip, threat_info)
            
            # Log response
            self._log_response(threat_info, response_action, success)
            
            # Send notifications
            self._send_notifications(threat_info, response_action)
            
            return success
            
        except Exception as e:
            logger.error(f"Error processing threat: {e}")
            return False
    
    def _determine_response_action(self, threat_type, severity, src_ip):
        """Determine appropriate response action based on threat type and severity"""
        # Check custom rules first
        for rule in self.response_rules:
            if self._rule_matches(rule, threat_type, severity, src_ip):
                return rule['action']
        
        # Default severity-based response
        threshold = self.severity_thresholds.get(severity, self.severity_thresholds['medium'])
        
        # Check for repeat offenders
        if self._is_repeat_offender(src_ip):
            if threshold['action'] == 'temp_block':
                threshold['duration'] *= 2  # Double block time for repeat offenders
            elif threshold['action'] == 'log':
                threshold = self.severity_thresholds['medium']  # Escalate to temp_block
        
        return {
            'type': threshold['action'],
            'duration': threshold['duration'],
            'threat_type': threat_type,
            'severity': severity
        }
    
    def _execute_response(self, action, src_ip, threat_info):
        """Execute the determined response action"""
        try:
            action_type = action.get('type')
            duration = action.get('duration', 0)
            
            if action_type == 'log':
                return self._log_only_response(src_ip, threat_info)
            
            elif action_type == 'temp_block':
                return self._temporary_block(src_ip, duration, threat_info)
            
            elif action_type == 'permanent_block':
                return self._permanent_block(src_ip, threat_info)
            
            elif action_type == 'rate_limit':
                return self._rate_limit(src_ip, action.get('rate', 10), threat_info)
            
            elif action_type == 'quarantine':
                return self._quarantine_ip(src_ip, duration, threat_info)
            
            else:
                logger.warning(f"Unknown action type: {action_type}")
                return False
                
        except Exception as e:
            logger.error(f"Error executing response: {e}")
            return False
    
    def _temporary_block(self, src_ip, duration, threat_info):
        """Implement temporary IP blocking"""
        try:
            with self.lock:
                # Check if already blocked
                if src_ip in self.blocked_ips:
                    logger.info(f"IP {src_ip} already blocked")
                    return True
                
                # Add iptables rule to block IP
                block_cmd = [
                    'iptables', '-I', 'INPUT', '-s', src_ip, '-j', 'DROP'
                ]
                
                result = subprocess.run(block_cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    # Track the block
                    expiry_time = datetime.now() + timedelta(seconds=duration)
                    self.temp_blocks[src_ip] = expiry_time
                    self.blocked_ips.add(src_ip)
                    
                    self.active_blocks[src_ip] = {
                        'type': 'temporary',
                        'start_time': datetime.now(),
                        'expiry_time': expiry_time,
                        'threat_info': threat_info,
                        'rule_cmd': block_cmd
                    }
                    
                    logger.security_event("IP_BLOCKED", 
                        f"Temporarily blocked IP {src_ip} for {duration} seconds", 
                        "WARNING")
                    
                    return True
                else:
                    logger.error(f"Failed to block IP {src_ip}: {result.stderr}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error in temporary block: {e}")
            return False
    
    def _permanent_block(self, src_ip, threat_info):
        """Implement permanent IP blocking"""
        try:
            with self.lock:
                # Add iptables rule to permanently block IP
                block_cmd = [
                    'iptables', '-I', 'INPUT', '-s', src_ip, '-j', 'DROP'
                ]
                
                result = subprocess.run(block_cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.blocked_ips.add(src_ip)
                    
                    self.active_blocks[src_ip] = {
                        'type': 'permanent',
                        'start_time': datetime.now(),
                        'expiry_time': None,
                        'threat_info': threat_info,
                        'rule_cmd': block_cmd
                    }
                    
                    # Also save to persistent storage
                    self._save_permanent_block(src_ip, threat_info)
                    
                    logger.security_event("IP_PERMANENTLY_BLOCKED", 
                        f"Permanently blocked IP {src_ip}", 
                        "CRITICAL")
                    
                    return True
                else:
                    logger.error(f"Failed to permanently block IP {src_ip}: {result.stderr}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error in permanent block: {e}")
            return False
    
    def _rate_limit(self, src_ip, rate_limit, threat_info):
        """Implement rate limiting for an IP"""
        try:
            # Create iptables rule for rate limiting
            limit_cmd = [
                'iptables', '-I', 'INPUT', '-s', src_ip, '-m', 'limit',
                '--limit', f"{rate_limit}/min", '--limit-burst', str(rate_limit),
                '-j', 'ACCEPT'
            ]
            
            drop_cmd = [
                'iptables', '-I', 'INPUT', '-s', src_ip, '-j', 'DROP'
            ]
            
            # Execute both commands
            limit_result = subprocess.run(limit_cmd, capture_output=True, text=True)
            drop_result = subprocess.run(drop_cmd, capture_output=True, text=True)
            
            if limit_result.returncode == 0 and drop_result.returncode == 0:
                self.active_blocks[src_ip] = {
                    'type': 'rate_limit',
                    'start_time': datetime.now(),
                    'rate_limit': rate_limit,
                    'threat_info': threat_info,
                    'rule_cmds': [limit_cmd, drop_cmd]
                }
                
                logger.security_event("IP_RATE_LIMITED", 
                    f"Rate limited IP {src_ip} to {rate_limit} connections/min", 
                    "INFO")
                
                return True
            else:
                logger.error(f"Failed to rate limit IP {src_ip}")
                return False
                
        except Exception as e:
            logger.error(f"Error in rate limiting: {e}")
            return False
    
    def _quarantine_ip(self, src_ip, duration, threat_info):
        """Quarantine IP to a honeypot network"""
        try:
            # Redirect traffic to honeypot instead of blocking
            quarantine_cmd = [
                'iptables', '-t', 'nat', '-I', 'PREROUTING', '-s', src_ip,
                '-j', 'DNAT', '--to-destination', '192.168.100.1'
            ]
            
            result = subprocess.run(quarantine_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                expiry_time = datetime.now() + timedelta(seconds=duration)
                self.active_blocks[src_ip] = {
                    'type': 'quarantine',
                    'start_time': datetime.now(),
                    'expiry_time': expiry_time,
                    'threat_info': threat_info,
                    'rule_cmd': quarantine_cmd
                }
                
                logger.security_event("IP_QUARANTINED", 
                    f"Quarantined IP {src_ip} for {duration} seconds", 
                    "WARNING")
                
                return True
            else:
                logger.error(f"Failed to quarantine IP {src_ip}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error in quarantine: {e}")
            return False
    
    def _log_only_response(self, src_ip, threat_info):
        """Log the threat without taking blocking action"""
        logger.security_event("THREAT_DETECTED", 
            f"Threat detected from {src_ip}: {threat_info}", 
            "INFO")
        return True
    
    def _cleanup_expired_blocks(self):
        """Background thread to cleanup expired temporary blocks"""
        while True:
            try:
                current_time = datetime.now()
                expired_ips = []
                
                with self.lock:
                    for ip, expiry_time in self.temp_blocks.items():
                        if current_time >= expiry_time:
                            expired_ips.append(ip)
                    
                    for ip in expired_ips:
                        self._unblock_ip(ip)
                        del self.temp_blocks[ip]
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Error in cleanup thread: {e}")
                time.sleep(60)
    
    def _unblock_ip(self, src_ip):
        """Remove IP block"""
        try:
            if src_ip in self.active_blocks:
                block_info = self.active_blocks[src_ip]
                
                # Remove iptables rule
                if block_info['type'] in ['temporary', 'permanent']:
                    unblock_cmd = [
                        'iptables', '-D', 'INPUT', '-s', src_ip, '-j', 'DROP'
                    ]
                    subprocess.run(unblock_cmd, capture_output=True, text=True)
                
                elif block_info['type'] == 'quarantine':
                    unblock_cmd = [
                        'iptables', '-t', 'nat', '-D', 'PREROUTING', '-s', src_ip,
                        '-j', 'DNAT', '--to-destination', '192.168.100.1'
                    ]
                    subprocess.run(unblock_cmd, capture_output=True, text=True)
                
                # Remove from tracking
                self.blocked_ips.discard(src_ip)
                del self.active_blocks[src_ip]
                
                logger.info(f"Unblocked IP {src_ip}")
                
        except Exception as e:
            logger.error(f"Error unblocking IP {src_ip}: {e}")
    
    def unblock_ip_manual(self, src_ip):
        """Manually unblock an IP address"""
        with self.lock:
            if src_ip in self.temp_blocks:
                del self.temp_blocks[src_ip]
            self._unblock_ip(src_ip)
            logger.security_event("IP_MANUALLY_UNBLOCKED", 
                f"IP {src_ip} manually unblocked", 
                "INFO")
            return True
        return False
    
    def get_blocked_ips(self):
        """Get list of currently blocked IPs"""
        with self.lock:
            return {
                'temporary': [
                    {
                        'ip': ip,
                        'expiry': expiry.isoformat(),
                        'remaining': (expiry - datetime.now()).total_seconds()
                    }
                    for ip, expiry in self.temp_blocks.items()
                ],
                'permanent': [
                    ip for ip, info in self.active_blocks.items()
                    if info['type'] == 'permanent'
                ],
                'quarantined': [
                    ip for ip, info in self.active_blocks.items()
                    if info['type'] == 'quarantine'
                ]
            }
    
    def _is_whitelisted(self, src_ip):
        """Check if IP is in whitelist"""
        whitelist = getattr(config, 'IP_WHITELIST', ['127.0.0.1', '::1'])
        return src_ip in whitelist
    
    def _is_repeat_offender(self, src_ip):
        """Check if IP has been blocked before recently"""
        recent_threshold = datetime.now() - timedelta(hours=24)
        for response in self.response_history:
            if (response.get('src_ip') == src_ip and 
                response.get('timestamp') > recent_threshold and
                response.get('action_type') in ['temp_block', 'permanent_block']):
                return True
        return False
    
    def _load_response_rules(self):
        """Load custom response rules from configuration"""
        try:
            rules_file = config.BASE_DIR / 'config' / 'response_rules.json'
            if rules_file.exists():
                with open(rules_file, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            logger.error(f"Error loading response rules: {e}")
            return []
    
    def _rule_matches(self, rule, threat_type, severity, src_ip):
        """Check if a custom rule matches the current threat"""
        if rule.get('threat_type') and rule['threat_type'] != threat_type:
            return False
        if rule.get('severity') and rule['severity'] != severity:
            return False
        if rule.get('src_ip_pattern'):
            import re
            if not re.match(rule['src_ip_pattern'], src_ip):
                return False
        return True
    
    def _log_response(self, threat_info, action, success):
        """Log response action"""
        response_log = {
            'timestamp': datetime.now(),
            'threat_info': threat_info,
            'action': action,
            'success': success,
            'src_ip': threat_info.get('src_ip')
        }
        self.response_history.append(response_log)
    
    def _send_notifications(self, threat_info, action):
        """Send notifications about the response"""
        if self.notification_manager:
            self.notification_manager.send_threat_notification(threat_info, action)
    
    def _save_permanent_block(self, src_ip, threat_info):
        """Save permanent block to persistent storage"""
        try:
            blocks_file = config.DATA_DIR / 'permanent_blocks.json'
            blocks = []
            
            if blocks_file.exists():
                with open(blocks_file, 'r') as f:
                    blocks = json.load(f)
            
            blocks.append({
                'ip': src_ip,
                'timestamp': datetime.now().isoformat(),
                'threat_info': threat_info
            })
            
            with open(blocks_file, 'w') as f:
                json.dump(blocks, f, indent=2)
                
        except Exception as e:
            logger.error(f"Error saving permanent block: {e}")
    
    def get_response_statistics(self):
        """Get response system statistics"""
        recent_threshold = datetime.now() - timedelta(hours=24)
        recent_responses = [
            r for r in self.response_history 
            if r['timestamp'] > recent_threshold
        ]
        
        stats = {
            'total_responses_24h': len(recent_responses),
            'blocked_ips_count': len(self.blocked_ips),
            'temporary_blocks': len(self.temp_blocks),
            'permanent_blocks': len([
                info for info in self.active_blocks.values()
                if info['type'] == 'permanent'
            ]),
            'response_types': defaultdict(int)
        }
        
        for response in recent_responses:
            action_type = response['action'].get('type', 'unknown')
            stats['response_types'][action_type] += 1
        
        return stats

def test_auto_response():
    """Test auto response system"""
    response_system = AutoResponseSystem()
    
    # Test threat processing
    test_threat = {
        'type': 'port_scan',
        'severity': 'high',
        'src_ip': '192.168.1.100',
        'details': {
            'ports_scanned': 50,
            'duration': 120
        }
    }
    
    print("Testing auto response system...")
    result = response_system.process_threat(test_threat)
    print(f"Response result: {result}")
    
    # Test statistics
    stats = response_system.get_response_statistics()
    print(f"Response statistics: {stats}")
    
    # Test blocked IPs
    blocked = response_system.get_blocked_ips()
    print(f"Blocked IPs: {blocked}")

if __name__ == "__main__":
    test_auto_response()
