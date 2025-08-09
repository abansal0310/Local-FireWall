import smtplib
import json
import requests
import threading
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import deque
from utils.logger import logger
from config.settings import config

class NotificationManager:
    """Centralized notification management system"""
    
    def __init__(self):
        self.notification_history = deque(maxlen=10000)
        self.rate_limits = {}  # {method: {timestamp: count}}
        self.notification_rules = self._load_notification_rules()
        
        # Rate limiting settings
        self.rate_limit_windows = {
            'email': {'window': 300, 'max_count': 10},    # 10 emails per 5 minutes
            'webhook': {'window': 60, 'max_count': 50},   # 50 webhooks per minute
            'sms': {'window': 600, 'max_count': 5}        # 5 SMS per 10 minutes
        }
        
        logger.info("NotificationManager initialized")
    
    def send_threat_notification(self, threat_info, response_action=None):
        """Send notification about detected threat"""
        try:
            # Determine notification methods based on severity
            severity = threat_info.get('severity', 'medium')
            methods = self._get_notification_methods(severity, threat_info)
            
            # Create notification content
            notification = self._create_threat_notification(threat_info, response_action)
            
            # Send via each method
            for method in methods:
                if self._check_rate_limit(method):
                    if method == 'email':
                        self._send_email_notification(notification)
                    elif method == 'webhook':
                        self._send_webhook_notification(notification)
                    elif method == 'sms':
                        self._send_sms_notification(notification)
                    elif method == 'slack':
                        self._send_slack_notification(notification)
                else:
                    logger.warning(f"Rate limit exceeded for {method}")
            
            # Record notification
            self._record_notification(notification, methods)
            
        except Exception as e:
            logger.error(f"Error sending threat notification: {e}")
    
    def send_system_notification(self, event_type, message, severity='info'):
        """Send system status notification"""
        try:
            notification = {
                'type': 'system',
                'event_type': event_type,
                'message': message,
                'severity': severity,
                'timestamp': datetime.now(),
                'hostname': self._get_hostname()
            }
            
            # Determine methods based on event type
            methods = self._get_system_notification_methods(event_type, severity)
            
            for method in methods:
                if self._check_rate_limit(method):
                    if method == 'email':
                        self._send_email_notification(notification)
                    elif method == 'webhook':
                        self._send_webhook_notification(notification)
                    elif method == 'slack':
                        self._send_slack_notification(notification)
            
            self._record_notification(notification, methods)
            
        except Exception as e:
            logger.error(f"Error sending system notification: {e}")
    
    def send_custom_notification(self, title, message, methods=None, severity='info'):
        """Send custom notification"""
        try:
            notification = {
                'type': 'custom',
                'title': title,
                'message': message,
                'severity': severity,
                'timestamp': datetime.now(),
                'hostname': self._get_hostname()
            }
            
            if not methods:
                methods = ['email']
            
            for method in methods:
                if self._check_rate_limit(method):
                    if method == 'email':
                        self._send_email_notification(notification)
                    elif method == 'webhook':
                        self._send_webhook_notification(notification)
                    elif method == 'slack':
                        self._send_slack_notification(notification)
            
            self._record_notification(notification, methods)
            
        except Exception as e:
            logger.error(f"Error sending custom notification: {e}")
    
    def _send_email_notification(self, notification):
        """Send email notification"""
        try:
            if not config.ENABLE_EMAIL_ALERTS:
                return False
            
            # Create email
            msg = MIMEMultipart()
            msg['From'] = config.EMAIL_FROM
            msg['To'] = config.EMAIL_TO
            msg['Subject'] = self._generate_email_subject(notification)
            
            # Create email body
            body = self._generate_email_body(notification)
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            with smtplib.SMTP(config.EMAIL_SMTP_SERVER, config.EMAIL_SMTP_PORT) as server:
                server.starttls()
                server.login(config.EMAIL_FROM, config.EMAIL_PASSWORD)
                server.send_message(msg)
            
            logger.info(f"Email notification sent: {notification.get('type')}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending email: {e}")
            return False
    
    def _send_webhook_notification(self, notification):
        """Send webhook notification"""
        try:
            webhook_url = getattr(config, 'WEBHOOK_URL', None)
            if not webhook_url:
                return False
            
            payload = {
                'timestamp': notification['timestamp'].isoformat(),
                'type': notification['type'],
                'severity': notification['severity'],
                'hostname': notification.get('hostname'),
                'data': notification
            }
            
            response = requests.post(
                webhook_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            
            if response.status_code == 200:
                logger.info("Webhook notification sent successfully")
                return True
            else:
                logger.error(f"Webhook failed with status {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending webhook: {e}")
            return False
    
    def _send_slack_notification(self, notification):
        """Send Slack notification"""
        try:
            slack_webhook = getattr(config, 'SLACK_WEBHOOK_URL', None)
            if not slack_webhook:
                return False
            
            # Create Slack message
            color = self._get_slack_color(notification['severity'])
            text = self._generate_slack_message(notification)
            
            payload = {
                'attachments': [{
                    'color': color,
                    'title': self._generate_slack_title(notification),
                    'text': text,
                    'timestamp': int(notification['timestamp'].timestamp())
                }]
            }
            
            response = requests.post(slack_webhook, json=payload, timeout=30)
            
            if response.status_code == 200:
                logger.info("Slack notification sent successfully")
                return True
            else:
                logger.error(f"Slack notification failed with status {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending Slack notification: {e}")
            return False
    
    def _send_sms_notification(self, notification):
        """Send SMS notification (placeholder for SMS service integration)"""
        try:
            # This would integrate with SMS service like Twilio
            sms_config = getattr(config, 'SMS_CONFIG', None)
            if not sms_config:
                return False
            
            message = self._generate_sms_message(notification)
            logger.info(f"SMS notification would be sent: {message[:100]}...")
            
            # Placeholder for actual SMS sending
            return True
            
        except Exception as e:
            logger.error(f"Error sending SMS: {e}")
            return False
    
    def _create_threat_notification(self, threat_info, response_action):
        """Create standardized threat notification"""
        return {
            'type': 'threat',
            'threat_type': threat_info.get('type'),
            'severity': threat_info.get('severity'),
            'src_ip': threat_info.get('src_ip'),
            'dst_ip': threat_info.get('dst_ip'),
            'details': threat_info.get('details', {}),
            'response_action': response_action,
            'timestamp': datetime.now(),
            'hostname': self._get_hostname()
        }
    
    def _get_notification_methods(self, severity, threat_info):
        """Determine notification methods based on severity and threat type"""
        methods = []
        
        # Check custom rules first
        for rule in self.notification_rules:
            if self._rule_matches_threat(rule, severity, threat_info):
                return rule.get('methods', ['email'])
        
        # Default severity-based methods
        if severity == 'critical':
            methods = ['email', 'slack', 'webhook', 'sms']
        elif severity == 'high':
            methods = ['email', 'slack', 'webhook']
        elif severity == 'medium':
            methods = ['email', 'webhook']
        else:  # low
            methods = ['webhook']
        
        return methods
    
    def _get_system_notification_methods(self, event_type, severity):
        """Get notification methods for system events"""
        if event_type in ['system_startup', 'system_shutdown']:
            return ['email', 'slack']
        elif event_type in ['high_cpu', 'high_memory', 'disk_full']:
            return ['email', 'webhook']
        elif severity in ['critical', 'error']:
            return ['email', 'slack']
        else:
            return ['webhook']
    
    def _check_rate_limit(self, method):
        """Check if notification method is within rate limits"""
        if method not in self.rate_limit_windows:
            return True
        
        current_time = datetime.now()
        window_config = self.rate_limit_windows[method]
        window_start = current_time - timedelta(seconds=window_config['window'])
        
        # Initialize if not exists
        if method not in self.rate_limits:
            self.rate_limits[method] = deque()
        
        # Remove old entries
        while (self.rate_limits[method] and 
               self.rate_limits[method][0] < window_start):
            self.rate_limits[method].popleft()
        
        # Check if under limit
        if len(self.rate_limits[method]) < window_config['max_count']:
            self.rate_limits[method].append(current_time)
            return True
        
        return False
    
    def _generate_email_subject(self, notification):
        """Generate email subject line"""
        ntype = notification['type']
        severity = notification['severity'].upper()
        
        if ntype == 'threat':
            threat_type = notification.get('threat_type', 'Unknown')
            return f"[{severity}] {threat_type.title()} Detected - Firewall IDS"
        elif ntype == 'system':
            event_type = notification.get('event_type', 'System Event')
            return f"[{severity}] {event_type.title()} - Firewall IDS"
        else:
            title = notification.get('title', 'Notification')
            return f"[{severity}] {title} - Firewall IDS"
    
    def _generate_email_body(self, notification):
        """Generate HTML email body"""
        if notification['type'] == 'threat':
            return self._generate_threat_email_body(notification)
        elif notification['type'] == 'system':
            return self._generate_system_email_body(notification)
        else:
            return self._generate_custom_email_body(notification)
    
    def _generate_threat_email_body(self, notification):
        """Generate threat detection email body"""
        html = f"""
        <html>
        <body>
        <h2 style="color: #d32f2f;">Security Threat Detected</h2>
        
        <table border="1" cellpadding="5" cellspacing="0">
        <tr><td><b>Threat Type:</b></td><td>{notification.get('threat_type', 'Unknown')}</td></tr>
        <tr><td><b>Severity:</b></td><td>{notification.get('severity', 'Unknown')}</td></tr>
        <tr><td><b>Source IP:</b></td><td>{notification.get('src_ip', 'Unknown')}</td></tr>
        <tr><td><b>Destination IP:</b></td><td>{notification.get('dst_ip', 'Unknown')}</td></tr>
        <tr><td><b>Timestamp:</b></td><td>{notification['timestamp']}</td></tr>
        <tr><td><b>Hostname:</b></td><td>{notification.get('hostname', 'Unknown')}</td></tr>
        </table>
        
        <h3>Details:</h3>
        <pre>{json.dumps(notification.get('details', {}), indent=2)}</pre>
        """
        
        if notification.get('response_action'):
            html += f"""
            <h3>Response Action:</h3>
            <pre>{json.dumps(notification['response_action'], indent=2)}</pre>
            """
        
        html += """
        <p><em>This is an automated message from the Firewall IDS System.</em></p>
        </body>
        </html>
        """
        
        return html
    
    def _generate_system_email_body(self, notification):
        """Generate system notification email body"""
        return f"""
        <html>
        <body>
        <h2>System Notification</h2>
        <p><b>Event:</b> {notification.get('event_type', 'Unknown')}</p>
        <p><b>Severity:</b> {notification.get('severity', 'Unknown')}</p>
        <p><b>Message:</b> {notification.get('message', 'No message')}</p>
        <p><b>Timestamp:</b> {notification['timestamp']}</p>
        <p><b>Hostname:</b> {notification.get('hostname', 'Unknown')}</p>
        <p><em>This is an automated message from the Firewall IDS System.</em></p>
        </body>
        </html>
        """
    
    def _generate_custom_email_body(self, notification):
        """Generate custom notification email body"""
        return f"""
        <html>
        <body>
        <h2>{notification.get('title', 'Notification')}</h2>
        <p>{notification.get('message', 'No message')}</p>
        <p><b>Timestamp:</b> {notification['timestamp']}</p>
        <p><b>Hostname:</b> {notification.get('hostname', 'Unknown')}</p>
        <p><em>This is an automated message from the Firewall IDS System.</em></p>
        </body>
        </html>
        """
    
    def _generate_slack_title(self, notification):
        """Generate Slack notification title"""
        if notification['type'] == 'threat':
            threat_type = notification.get('threat_type', 'Unknown')
            return f"🚨 {threat_type.title()} Detected"
        elif notification['type'] == 'system':
            event_type = notification.get('event_type', 'System Event')
            return f"⚠️ {event_type.title()}"
        else:
            return f"📢 {notification.get('title', 'Notification')}"
    
    def _generate_slack_message(self, notification):
        """Generate Slack notification message"""
        if notification['type'] == 'threat':
            return (f"Source IP: {notification.get('src_ip', 'Unknown')}\n"
                   f"Severity: {notification.get('severity', 'Unknown')}\n"
                   f"Time: {notification['timestamp']}")
        else:
            return notification.get('message', 'No additional details')
    
    def _generate_sms_message(self, notification):
        """Generate SMS notification message"""
        if notification['type'] == 'threat':
            return (f"SECURITY ALERT: {notification.get('threat_type', 'Unknown')} "
                   f"from {notification.get('src_ip', 'Unknown')} "
                   f"at {notification['timestamp'].strftime('%H:%M')}")
        else:
            return f"SYSTEM: {notification.get('message', 'Alert')}"
    
    def _get_slack_color(self, severity):
        """Get Slack color based on severity"""
        colors = {
            'critical': '#d32f2f',
            'high': '#f57c00',
            'medium': '#fbc02d',
            'low': '#388e3c',
            'info': '#1976d2'
        }
        return colors.get(severity, '#757575')
    
    def _get_hostname(self):
        """Get system hostname"""
        import socket
        try:
            return socket.gethostname()
        except:
            return 'unknown'
    
    def _load_notification_rules(self):
        """Load notification rules from configuration"""
        try:
            rules_file = config.BASE_DIR / 'config' / 'notification_rules.json'
            if rules_file.exists():
                with open(rules_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error loading notification rules: {e}")
        
        return []
    
    def _rule_matches_threat(self, rule, severity, threat_info):
        """Check if notification rule matches threat"""
        conditions = rule.get('conditions', {})
        
        if 'severity' in conditions and conditions['severity'] != severity:
            return False
        
        if 'threat_type' in conditions and conditions['threat_type'] != threat_info.get('type'):
            return False
        
        return True
    
    def _record_notification(self, notification, methods):
        """Record notification in history"""
        record = {
            'timestamp': notification['timestamp'],
            'type': notification['type'],
            'severity': notification['severity'],
            'methods': methods,
            'notification_id': id(notification)
        }
        self.notification_history.append(record)
    
    def get_notification_statistics(self, hours=24):
        """Get notification statistics"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        recent_notifications = [
            n for n in self.notification_history
            if n['timestamp'] > cutoff_time
        ]
        
        stats = {
            'total_notifications': len(recent_notifications),
            'by_type': {},
            'by_severity': {},
            'by_method': {},
            'rate_limit_hits': 0
        }
        
        for notification in recent_notifications:
            # Count by type
            ntype = notification.get('type', 'unknown')
            stats['by_type'][ntype] = stats['by_type'].get(ntype, 0) + 1
            
            # Count by severity
            severity = notification.get('severity', 'unknown')
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
            
            # Count by method
            for method in notification.get('methods', []):
                stats['by_method'][method] = stats['by_method'].get(method, 0) + 1
        
        return stats

def test_notification_manager():
    """Test notification manager"""
    nm = NotificationManager()
    
    # Test threat notification
    threat_info = {
        'type': 'port_scan',
        'severity': 'high',
        'src_ip': '192.168.1.100',
        'details': {'ports': [22, 80, 443]}
    }
    
    nm.send_threat_notification(threat_info)
    
    # Test system notification
    nm.send_system_notification('high_cpu', 'CPU usage at 95%', 'warning')
    
    # Test custom notification
    nm.send_custom_notification('Test Alert', 'This is a test message')
    
    # Get statistics
    stats = nm.get_notification_statistics()
    print(f"Notification statistics: {stats}")

if __name__ == "__main__":
    test_notification_manager()
