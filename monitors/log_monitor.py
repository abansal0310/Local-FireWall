import threading
import time
import re
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from utils.logger import logger
from config.settings import config

class LogFileHandler(FileSystemEventHandler):
    """Handle log file changes"""
    
    def __init__(self, log_monitor):
        self.log_monitor = log_monitor
    
    def on_modified(self, event):
        if not event.is_directory:
            self.log_monitor.process_log_file(event.src_path)

class LogMonitor:
    """System log file monitoring for security events"""
    
    def __init__(self):
        self.running = False
        self.observer = Observer()
        self.monitor_thread = None
        
        # Log files to monitor
        self.log_files = [
            '/var/log/auth.log',      # Authentication logs
            '/var/log/secure',        # Security logs (RHEL/CentOS)
            '/var/log/syslog',        # System logs
            '/var/log/kern.log',      # Kernel logs
            '/var/log/messages'       # General messages
        ]
        
        # Pattern matching for security events
        self.patterns = {
            'failed_login': [
                r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)',
                r'authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)',
                r'Invalid user .* from (\d+\.\d+\.\d+\.\d+)'
            ],
            'successful_login': [
                r'Accepted password for .* from (\d+\.\d+\.\d+\.\d+)',
                r'session opened for user .* from (\d+\.\d+\.\d+\.\d+)'
            ],
            'brute_force': [
                r'multiple authentication failures.*from (\d+\.\d+\.\d+\.\d+)',
                r'repeated login failures.*from (\d+\.\d+\.\d+\.\d+)'
            ],
            'privilege_escalation': [
                r'sudo.*COMMAND=(.+)',
                r'su.*session opened for user root'
            ],
            'system_changes': [
                r'iptables.*-A',
                r'kernel.*firewall',
                r'service.*started|stopped'
            ]
        }
        
        # Event tracking
        self.failed_logins = defaultdict(list)  # {ip: [timestamps]}
        self.successful_logins = defaultdict(list)
        self.security_events = deque(maxlen=1000)
        
        # File positions to track what we've already read
        self.file_positions = {}
        
        logger.info("LogMonitor initialized")
    
    def start_monitoring(self):
        """Start log monitoring"""
        if self.running:
            logger.warning("Log monitoring already running")
            return
        
        self.running = True
        
        # Setup file watcher
        for log_file in self.log_files:
            if Path(log_file).exists():
                log_dir = Path(log_file).parent
                self.observer.schedule(LogFileHandler(self), str(log_dir), recursive=False)
                logger.info(f"Monitoring log file: {log_file}")
        
        # Start observer
        self.observer.start()
        
        # Start monitoring thread for initial file reading
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info("Log monitoring started")
    
    def stop_monitoring(self):
        """Stop log monitoring"""
        self.running = False
        self.observer.stop()
        self.observer.join()
        
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        
        logger.info("Log monitoring stopped")
    
    def _monitor_loop(self):
        """Initial processing of existing log files"""
        try:
            # Process existing log files
            for log_file in self.log_files:
                if Path(log_file).exists():
                    self.process_log_file(log_file, initial=True)
            
            # Keep thread alive for real-time processing
            while self.running:
                self._cleanup_old_events()
                time.sleep(60)  # Cleanup every minute
                
        except Exception as e:
            logger.error(f"Error in log monitoring loop: {e}")
    
    def process_log_file(self, log_file_path, initial=False):
        """Process log file for security events"""
        try:
            log_file = Path(log_file_path)
            if not log_file.exists():
                return
            
            # Get current file position
            current_pos = self.file_positions.get(str(log_file), 0)
            
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                # Seek to last position (skip for initial processing)
                if not initial:
                    f.seek(current_pos)
                
                # Read new lines
                new_lines = f.readlines()
                
                # Update file position
                self.file_positions[str(log_file)] = f.tell()
                
                # Process each line
                for line in new_lines:
                    self._analyze_log_line(line.strip(), str(log_file))
                    
        except PermissionError:
            logger.warning(f"Permission denied reading {log_file_path}")
        except Exception as e:
            logger.error(f"Error processing log file {log_file_path}: {e}")
    
    def _analyze_log_line(self, line, source_file):
        """Analyze individual log line for security events"""
        if not line:
            return
        
        timestamp = self._extract_timestamp(line)
        
        # Check each pattern category
        for event_type, patterns in self.patterns.items():
            for pattern in patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    self._handle_security_event(event_type, line, match, timestamp, source_file)
                    break
    
    def _extract_timestamp(self, line):
        """Extract timestamp from log line"""
        # Common log timestamp patterns
        timestamp_patterns = [
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',  # Jan 15 10:30:45
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',   # 2024-01-15T10:30:45
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})'  # 2024-01-15 10:30:45
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                try:
                    # Try to parse the timestamp
                    timestamp_str = match.group(1)
                    # Add year for syslog format
                    if not timestamp_str.startswith('20'):
                        timestamp_str = f"{datetime.now().year} {timestamp_str}"
                    return datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")
                except ValueError:
                    pass
        
        # Return current time if parsing fails
        return datetime.now()
    
    def _handle_security_event(self, event_type, line, match, timestamp, source_file):
        """Handle detected security event"""
        
        # Extract IP address if present
        ip_address = None
        if match.groups():
            ip_address = match.group(1)
        
        # Create event record
        event = {
            'timestamp': timestamp,
            'event_type': event_type,
            'line': line,
            'ip_address': ip_address,
            'source_file': source_file
        }
        
        # Add to security events
        self.security_events.append(event)
        
        # Handle specific event types
        if event_type == 'failed_login' and ip_address:
            self.failed_logins[ip_address].append(timestamp)
            self._check_brute_force(ip_address)
            
        elif event_type == 'successful_login' and ip_address:
            self.successful_logins[ip_address].append(timestamp)
        
        # Log security event
        severity = self._get_event_severity(event_type)
        logger.security_event(event_type.upper(), 
            f"Event detected from {ip_address or 'unknown'}: {line[:100]}", 
            severity)
    
    def _check_brute_force(self, ip_address):
        """Check for brute force attack patterns"""
        now = datetime.now()
        time_window = timedelta(minutes=config.BRUTE_FORCE_TIME_WINDOW // 60)
        
        # Count recent failed logins
        recent_failures = [
            ts for ts in self.failed_logins[ip_address]
            if now - ts <= time_window
        ]
        
        if len(recent_failures) >= config.BRUTE_FORCE_THRESHOLD:
            logger.security_event("BRUTE_FORCE_DETECTED", 
                f"Brute force attack detected from {ip_address}: {len(recent_failures)} failed logins in {config.BRUTE_FORCE_TIME_WINDOW // 60} minutes", 
                "CRITICAL")
            
            return True
        
        return False
    
    def _get_event_severity(self, event_type):
        """Get severity level for event type"""
        severity_map = {
            'failed_login': 'WARNING',
            'successful_login': 'INFO',
            'brute_force': 'CRITICAL',
            'privilege_escalation': 'ERROR',
            'system_changes': 'WARNING'
        }
        return severity_map.get(event_type, 'INFO')
    
    def _cleanup_old_events(self):
        """Clean up old events and login attempts"""
        cutoff_time = datetime.now() - timedelta(hours=24)
        
        # Clean up failed logins
        for ip in list(self.failed_logins.keys()):
            self.failed_logins[ip] = [
                ts for ts in self.failed_logins[ip] 
                if ts > cutoff_time
            ]
            if not self.failed_logins[ip]:
                del self.failed_logins[ip]
        
        # Clean up successful logins
        for ip in list(self.successful_logins.keys()):
            self.successful_logins[ip] = [
                ts for ts in self.successful_logins[ip] 
                if ts > cutoff_time
            ]
            if not self.successful_logins[ip]:
                del self.successful_logins[ip]
    
    def get_failed_login_stats(self):
        """Get failed login statistics"""
        stats = {}
        for ip, timestamps in self.failed_logins.items():
            recent = [ts for ts in timestamps if datetime.now() - ts <= timedelta(hours=1)]
            stats[ip] = {
                'total_failures': len(timestamps),
                'recent_failures': len(recent),
                'first_attempt': min(timestamps) if timestamps else None,
                'last_attempt': max(timestamps) if timestamps else None
            }
        return stats
    
    def get_recent_events(self, limit=50):
        """Get recent security events"""
        return list(self.security_events)[-limit:]
    
    def get_statistics(self):
        """Get monitoring statistics"""
        return {
            'running': self.running,
            'monitored_files': len([f for f in self.log_files if Path(f).exists()]),
            'total_events': len(self.security_events),
            'failed_login_ips': len(self.failed_logins),
            'successful_login_ips': len(self.successful_logins),
            'file_positions': len(self.file_positions)
        }

# Test function
def test_log_monitor():
    """Test log monitor functionality"""
    monitor = LogMonitor()
    
    print("Testing LogMonitor...")
    
    # Test pattern matching
    test_lines = [
        "Jan 15 10:30:45 server sshd[1234]: Failed password for user from 192.168.1.100",
        "Jan 15 10:31:00 server sshd[1235]: Accepted password for admin from 192.168.1.10",
        "Jan 15 10:31:15 server sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/ls"
    ]
    
    for line in test_lines:
        monitor._analyze_log_line(line, "test.log")
    
    # Get statistics
    stats = monitor.get_statistics()
    print(f"Statistics: {stats}")
    
    # Get recent events
    events = monitor.get_recent_events()
    print(f"Recent events: {len(events)}")
    
    for event in events:
        print(f"  {event['event_type']}: {event['line'][:50]}...")

if __name__ == "__main__":
    test_log_monitor()