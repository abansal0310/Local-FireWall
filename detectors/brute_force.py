import re
from datetime import datetime, timedelta
from collections import defaultdict, deque
from utils.logger import logger
from config.settings import config

class BruteForceDetector:
    """Brute force attack detection system"""
    
    def __init__(self):
        # Configuration
        self.threshold = config.BRUTE_FORCE_THRESHOLD
        self.time_window = config.BRUTE_FORCE_TIME_WINDOW
        
        # Attack tracking
        self.failed_attempts = defaultdict(lambda: deque())  # {ip: [timestamps]}
        self.successful_logins = defaultdict(lambda: deque())
        self.failed_users = defaultdict(lambda: defaultdict(list))  # {ip: {user: [timestamps]}}
        self.password_patterns = defaultdict(set)  # {ip: {password_patterns}}
        
        # Detection results
        self.detected_attacks = deque(maxlen=1000)
        
        # Service patterns for different login services
        self.service_patterns = {
            'ssh': {
                'failed': [
                    r'Failed password for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)',
                    r'authentication failure.*user=(\w+).*rhost=(\d+\.\d+\.\d+\.\d+)',
                    r'Invalid user (\w+) from (\d+\.\d+\.\d+\.\d+)'
                ],
                'success': [
                    r'Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+)',
                    r'session opened for user (\w+).*from (\d+\.\d+\.\d+\.\d+)'
                ]
            },
            'ftp': {
                'failed': [
                    r'FTP.*authentication failed.*user (\w+).*from (\d+\.\d+\.\d+\.\d+)',
                    r'FTP.*login failed.*user (\w+).*from (\d+\.\d+\.\d+\.\d+)'
                ],
                'success': [
                    r'FTP.*login successful.*user (\w+).*from (\d+\.\d+\.\d+\.\d+)'
                ]
            },
            'web': {
                'failed': [
                    r'HTTP.*401.*user (\w+).*from (\d+\.\d+\.\d+\.\d+)',
                    r'web.*authentication failed.*user (\w+).*from (\d+\.\d+\.\d+\.\d+)'
                ],
                'success': [
                    r'HTTP.*200.*user (\w+).*login.*from (\d+\.\d+\.\d+\.\d+)'
                ]
            },
            'rdp': {
                'failed': [
                    r'RDP.*authentication failed.*user (\w+).*from (\d+\.\d+\.\d+\.\d+)',
                    r'logon failure.*user (\w+).*from (\d+\.\d+\.\d+\.\d+)'
                ],
                'success': [
                    r'RDP.*successful logon.*user (\w+).*from (\d+\.\d+\.\d+\.\d+)'
                ]
            }
        }
        
        # Common password patterns to detect
        self.common_patterns = [
            r'password\d*',
            r'admin\d*',
            r'user\d*',
            r'test\d*',
            r'123456',
            r'qwerty',
            r'letmein'
        ]
        
        logger.info("BruteForceDetector initialized")
    
    def analyze_log_line(self, log_line, timestamp=None):
        """Analyze log line for brute force attack indicators"""
        if not log_line:
            return None
        
        if not timestamp:
            timestamp = datetime.now()
        
        # Try to match against service patterns
        for service, patterns in self.service_patterns.items():
            # Check failed attempts
            for pattern in patterns['failed']:
                match = re.search(pattern, log_line, re.IGNORECASE)
                if match:
                    return self._handle_failed_attempt(match, service, timestamp, log_line)
            
            # Check successful logins
            for pattern in patterns['success']:
                match = re.search(pattern, log_line, re.IGNORECASE)
                if match:
                    return self._handle_successful_login(match, service, timestamp, log_line)
        
        return None
    
    def analyze_network_packet(self, packet_info):
        """Analyze network packet for brute force indicators"""
        if not packet_info:
            return None
        
        # Look for multiple connection attempts to authentication ports
        dst_port = packet_info.get('dst_port')
        src_ip = packet_info.get('src_ip')
        timestamp = packet_info.get('timestamp', datetime.now())
        
        # Common authentication ports
        auth_ports = {22: 'ssh', 21: 'ftp', 23: 'telnet', 3389: 'rdp', 
                     80: 'http', 443: 'https', 993: 'imaps', 995: 'pop3s'}
        
        if dst_port in auth_ports and src_ip:
            # Track connection attempts to auth services
            self._track_auth_connections(src_ip, dst_port, auth_ports[dst_port], timestamp)
        
        return None
    
    def _handle_failed_attempt(self, match, service, timestamp, log_line):
        """Handle failed login attempt"""
        try:
            if len(match.groups()) >= 2:
                username = match.group(1)
                ip_address = match.group(2)
            else:
                # Fallback pattern matching
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', log_line)
                user_match = re.search(r'user[:\s]+(\w+)', log_line, re.IGNORECASE)
                
                if ip_match and user_match:
                    ip_address = ip_match.group(1)
                    username = user_match.group(1)
                else:
                    return None
            
            # Record failed attempt
            self.failed_attempts[ip_address].append(timestamp)
            self.failed_users[ip_address][username].append(timestamp)
            
            # Clean old data
            self._clean_old_attempts(ip_address, timestamp)
            
            # Check for brute force attack
            attack_result = self._detect_brute_force_attack(ip_address, username, service, timestamp)
            
            if attack_result:
                logger.security_event("BRUTE_FORCE_DETECTED", 
                    f"Brute force attack detected: {service} from {ip_address} targeting user {username}", 
                    "CRITICAL")
                
                return attack_result
            
        except Exception as e:
            logger.error(f"Error handling failed attempt: {e}")
        
        return None
    
    def _handle_successful_login(self, match, service, timestamp, log_line):
        """Handle successful login"""
        try:
            if len(match.groups()) >= 2:
                username = match.group(1)
                ip_address = match.group(2)
            else:
                return None
            
            # Record successful login
            self.successful_logins[ip_address].append((timestamp, username, service))
            
            # Check if this IP had recent failed attempts (possible successful brute force)
            if ip_address in self.failed_attempts:
                recent_failures = self._count_recent_attempts(ip_address, timestamp)
                if recent_failures >= self.threshold // 2:  # Lower threshold for successful after failures
                    logger.security_event("SUCCESSFUL_BRUTE_FORCE", 
                        f"Successful login from {ip_address} after {recent_failures} failed attempts", 
                        "ERROR")
                    
                    return {
                        'attack_type': 'successful_brute_force',
                        'ip_address': ip_address,
                        'username': username,
                        'service': service,
                        'previous_failures': recent_failures,
                        'timestamp': timestamp
                    }
            
        except Exception as e:
            logger.error(f"Error handling successful login: {e}")
        
        return None
    
    def _track_auth_connections(self, ip_address, port, service, timestamp):
        """Track connection attempts to authentication services"""
        # This could be expanded to detect connection-based brute force
        # For now, we'll just log suspicious connection patterns
        
        # Count connections in time window
        cutoff_time = timestamp - timedelta(seconds=self.time_window)
        
        # Simple connection tracking (this could be enhanced)
        if not hasattr(self, 'connection_attempts'):
            self.connection_attempts = defaultdict(lambda: deque())
        
        self.connection_attempts[f"{ip_address}:{port}"].append(timestamp)
        
        # Clean old connections
        self.connection_attempts[f"{ip_address}:{port}"] = deque([
            t for t in self.connection_attempts[f"{ip_address}:{port}"] 
            if t > cutoff_time
        ])
        
        # Check for suspicious connection rate
        connection_count = len(self.connection_attempts[f"{ip_address}:{port}"])
        if connection_count > 50:  # High connection rate
            logger.security_event("HIGH_AUTH_CONNECTIONS", 
                f"High connection rate to {service} from {ip_address}: {connection_count} connections", 
                "WARNING")
    
    def _detect_brute_force_attack(self, ip_address, username, service, timestamp):
        """Detect brute force attack patterns"""
        recent_failures = self._count_recent_attempts(ip_address, timestamp)
        
        # Basic threshold check
        if recent_failures >= self.threshold:
            attack_type = self._classify_attack_type(ip_address, username, service)
            
            detection = {
                'attack_type': attack_type,
                'ip_address': ip_address,
                'username': username,
                'service': service,
                'failure_count': recent_failures,
                'time_window': self.time_window,
                'timestamp': timestamp,
                'severity': self._calculate_severity(recent_failures, ip_address),
                'pattern_analysis': self._analyze_attack_patterns(ip_address)
            }
            
            self.detected_attacks.append(detection)
            return detection
        
        return None
    
    def _classify_attack_type(self, ip_address, username, service):
        """Classify the type of brute force attack"""
        user_count = len(self.failed_users[ip_address])
        
        if user_count == 1:
            return 'password_spray'  # Single user, multiple passwords
        elif user_count > 10:
            return 'credential_stuffing'  # Many users, likely credential lists
        else:
            return 'brute_force'  # Standard brute force
    
    def _calculate_severity(self, failure_count, ip_address):
        """Calculate attack severity"""
        base_severity = min(failure_count / self.threshold, 3.0)  # Max 3x threshold
        
        # Increase severity for multiple users targeted
        user_count = len(self.failed_users[ip_address])
        user_factor = min(user_count / 5, 2.0)  # Max 2x for user count
        
        # Check if IP has attacked before
        repeat_factor = 1.0
        for attack in self.detected_attacks:
            if attack['ip_address'] == ip_address:
                repeat_factor = 1.5
                break
        
        total_severity = base_severity * user_factor * repeat_factor
        
        if total_severity >= 6.0:
            return 'critical'
        elif total_severity >= 3.0:
            return 'high'
        elif total_severity >= 1.5:
            return 'medium'
        else:
            return 'low'
    
    def _analyze_attack_patterns(self, ip_address):
        """Analyze attack patterns for additional intelligence"""
        analysis = {
            'unique_users_targeted': len(self.failed_users[ip_address]),
            'attack_duration': 0,
            'attack_rate': 0,
            'user_enumeration': False
        }
        
        # Calculate attack duration and rate
        if self.failed_attempts[ip_address]:
            timestamps = list(self.failed_attempts[ip_address])
            analysis['attack_duration'] = (timestamps[-1] - timestamps[0]).total_seconds()
            analysis['attack_rate'] = len(timestamps) / max(analysis['attack_duration'], 1)
        
        # Check for user enumeration patterns
        users = list(self.failed_users[ip_address].keys())
        common_users = ['admin', 'administrator', 'root', 'user', 'test', 'guest']
        if any(user.lower() in common_users for user in users):
            analysis['user_enumeration'] = True
        
        return analysis
    
    def _count_recent_attempts(self, ip_address, current_time):
        """Count recent failed attempts from IP"""
        cutoff_time = current_time - timedelta(seconds=self.time_window)
        recent_attempts = [t for t in self.failed_attempts[ip_address] if t > cutoff_time]
        return len(recent_attempts)
    
    def _clean_old_attempts(self, ip_address, current_time):
        """Clean old attempt data"""
        cutoff_time = current_time - timedelta(seconds=self.time_window * 2)
        
        # Clean failed attempts
        self.failed_attempts[ip_address] = deque([
            t for t in self.failed_attempts[ip_address] if t > cutoff_time
        ])
        
        # Clean failed users
        for username in list(self.failed_users[ip_address].keys()):
            self.failed_users[ip_address][username] = [
                t for t in self.failed_users[ip_address][username] if t > cutoff_time
            ]
            if not self.failed_users[ip_address][username]:
                del self.failed_users[ip_address][username]
        
        # Remove empty entries
        if not self.failed_attempts[ip_address]:
            del self.failed_attempts[ip_address]
        if not self.failed_users[ip_address]:
            del self.failed_users[ip_address]
    
    def get_attack_statistics(self):
        """Get brute force attack statistics"""
        total_attacks = len(self.detected_attacks)
        
        # Recent attacks (last hour)
        recent_cutoff = datetime.now() - timedelta(hours=1)
        recent_attacks = [attack for attack in self.detected_attacks 
                         if attack['timestamp'] > recent_cutoff]
        
        # Attack type distribution
        attack_types = defaultdict(int)
        service_distribution = defaultdict(int)
        severity_distribution = defaultdict(int)
        
        for attack in self.detected_attacks:
            attack_types[attack['attack_type']] += 1
            service_distribution[attack['service']] += 1
            severity_distribution[attack['severity']] += 1
        
        return {
            'total_attacks': total_attacks,
            'recent_attacks': len(recent_attacks),
            'active_attackers': len(self.failed_attempts),
            'attack_type_distribution': dict(attack_types),
            'service_distribution': dict(service_distribution),
            'severity_distribution': dict(severity_distribution),
            'configuration': {
                'threshold': self.threshold,
                'time_window': self.time_window
            }
        }
    
    def get_top_attackers(self, limit=10):
        """Get top brute force attackers"""
        attacker_stats = defaultdict(lambda: {
            'attack_count': 0, 
            'services_targeted': set(), 
            'users_targeted': set(),
            'last_attack': None,
            'total_failures': 0
        })
        
        # Analyze detected attacks
        for attack in self.detected_attacks:
            ip = attack['ip_address']
            attacker_stats[ip]['attack_count'] += 1
            attacker_stats[ip]['services_targeted'].add(attack['service'])
            attacker_stats[ip]['users_targeted'].add(attack['username'])
            
            if not attacker_stats[ip]['last_attack'] or attack['timestamp'] > attacker_stats[ip]['last_attack']:
                attacker_stats[ip]['last_attack'] = attack['timestamp']
        
        # Add current failure counts
        for ip, failures in self.failed_attempts.items():
            attacker_stats[ip]['total_failures'] = len(failures)
        
        # Convert to list and sort
        top_attackers = []
        for ip, stats in attacker_stats.items():
            top_attackers.append({
                'ip': ip,
                'attack_count': stats['attack_count'],
                'total_failures': stats['total_failures'],
                'services_targeted': list(stats['services_targeted']),
                'users_targeted': list(stats['users_targeted']),
                'last_attack': stats['last_attack']
            })
        
        top_attackers.sort(key=lambda x: (x['attack_count'], x['total_failures']), reverse=True)
        return top_attackers[:limit]
    
    def cleanup_old_data(self):
        """Clean up old attack data"""
        cutoff_time = datetime.now() - timedelta(hours=24)
        
        # Clean up old detections
        self.detected_attacks = deque([
            attack for attack in self.detected_attacks 
            if attack['timestamp'] > cutoff_time
        ], maxlen=1000)

# Test function
    def get_active_attacks(self):
        """Get currently active brute force attacks"""
        current_time = datetime.now()
        active_attacks = []
        
        # Check recent detections
        cutoff_time = current_time - timedelta(seconds=self.time_window)
        
        for detection in self.detected_attacks:
            if detection['timestamp'] >= cutoff_time:
                active_attacks.append(detection)
        
        return active_attacks

def test_brute_force_detector():
    """Test brute force detector functionality"""
    detector = BruteForceDetector()
    
    print("Testing BruteForceDetector...")
    
    # Test log line analysis
    test_logs = [
        "Jan 15 10:30:45 server sshd[1234]: Failed password for admin from 192.168.1.100",
        "Jan 15 10:30:50 server sshd[1235]: Failed password for root from 192.168.1.100",
        "Jan 15 10:30:55 server sshd[1236]: Failed password for user from 192.168.1.100",
        "Jan 15 10:31:00 server sshd[1237]: Failed password for test from 192.168.1.100",
        "Jan 15 10:31:05 server sshd[1238]: Failed password for guest from 192.168.1.100",
        "Jan 15 10:31:10 server sshd[1239]: Failed password for admin from 192.168.1.100",
        "Jan 15 10:31:15 server sshd[1240]: Accepted password for admin from 192.168.1.100"
    ]
    
    base_time = datetime.now()
    for i, log_line in enumerate(test_logs):
        timestamp = base_time + timedelta(seconds=i*5)
        result = detector.analyze_log_line(log_line, timestamp)
        if result:
            print(f"Attack detected: {result}")
    
    # Get statistics
    stats = detector.get_attack_statistics()
    print(f"Attack statistics: {stats}")
    
    # Get top attackers
    top_attackers = detector.get_top_attackers()
    print(f"Top attackers: {top_attackers}")

if __name__ == "__main__":
    test_brute_force_detector()