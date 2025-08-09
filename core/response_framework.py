import threading
import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
from utils.logger import logger
from config.settings import config
from responses.auto_response import AutoResponseSystem
from responses.manual_review import ManualReviewInterface
from utils.notifier import NotificationManager

class ResponseActionFramework:
    """Centralized response action coordination framework"""
    
    def __init__(self):
        # Initialize response components
        self.auto_response = AutoResponseSystem()
        self.manual_review = ManualReviewInterface()
        self.notification_manager = NotificationManager()
        
        # Action queues
        self.immediate_actions = deque(maxlen=1000)
        self.scheduled_actions = []
        self.action_history = deque(maxlen=10000)
        
        # Processing threads
        self.action_processor = None
        self.scheduler_thread = None
        self.running = False
        
        # Response policies
        self.response_policies = self._load_response_policies()
        
        # Action templates
        self.action_templates = {
            'block_ip': {
                'type': 'auto_response',
                'action': 'block',
                'reversible': True,
                'timeout': 3600  # 1 hour default
            },
            'rate_limit': {
                'type': 'auto_response',
                'action': 'rate_limit',
                'reversible': True,
                'timeout': 1800  # 30 minutes
            },
            'manual_review': {
                'type': 'manual_review',
                'priority': 'medium',
                'timeout': 86400  # 24 hours
            },
            'alert_only': {
                'type': 'notification',
                'methods': ['email', 'webhook']
            }
        }
        
        logger.info("ResponseActionFramework initialized")
    
    def start(self):
        """Start the response action framework"""
        if self.running:
            logger.warning("Response framework already running")
            return
        
        self.running = True
        
        # Start action processor
        self.action_processor = threading.Thread(target=self._process_actions, daemon=True)
        self.action_processor.start()
        
        # Start scheduler
        self.scheduler_thread = threading.Thread(target=self._process_scheduled_actions, daemon=True)
        self.scheduler_thread.start()
        
        logger.info("Response action framework started")
    
    def stop(self):
        """Stop the response action framework"""
        self.running = False
        
        if self.action_processor and self.action_processor.is_alive():
            self.action_processor.join(timeout=5)
        
        if self.scheduler_thread and self.scheduler_thread.is_alive():
            self.scheduler_thread.join(timeout=5)
        
        logger.info("Response action framework stopped")
    
    def process_detection(self, detection_info):
        """Process a security detection and determine appropriate response"""
        try:
            detection_id = self._generate_detection_id()
            
            # Enrich detection with context
            enriched_detection = self._enrich_detection(detection_info)
            
            # Determine response actions
            actions = self._determine_response_actions(enriched_detection)
            
            # Queue actions for execution
            for action in actions:
                action['detection_id'] = detection_id
                action['detection_info'] = enriched_detection
                action['timestamp'] = datetime.now()
                
                if action.get('immediate', True):
                    self.immediate_actions.append(action)
                else:
                    self._schedule_action(action)
            
            logger.info(f"Queued {len(actions)} actions for detection {detection_id}")
            return detection_id
            
        except Exception as e:
            logger.error(f"Error processing detection: {e}")
            return None
    
    def process_manual_action(self, action_type, params, analyst_id):
        """Process manually triggered action"""
        try:
            action = {
                'id': self._generate_action_id(),
                'type': 'manual',
                'action_type': action_type,
                'params': params,
                'analyst_id': analyst_id,
                'timestamp': datetime.now(),
                'immediate': True
            }
            
            self.immediate_actions.append(action)
            logger.info(f"Queued manual action {action_type} by {analyst_id}")
            return action['id']
            
        except Exception as e:
            logger.error(f"Error processing manual action: {e}")
            return None
    
    def _process_actions(self):
        """Main action processing loop"""
        logger.info("Action processor started")
        
        while self.running:
            try:
                if self.immediate_actions:
                    action = self.immediate_actions.popleft()
                    self._execute_action(action)
                else:
                    time.sleep(0.1)  # Short sleep when no actions
                    
            except Exception as e:
                logger.error(f"Error in action processor: {e}")
                time.sleep(1)
    
    def _process_scheduled_actions(self):
        """Process scheduled actions"""
        logger.info("Action scheduler started")
        
        while self.running:
            try:
                current_time = datetime.now()
                due_actions = []
                
                # Find due actions
                for action in self.scheduled_actions[:]:
                    if action.get('scheduled_time', current_time) <= current_time:
                        due_actions.append(action)
                        self.scheduled_actions.remove(action)
                
                # Execute due actions
                for action in due_actions:
                    self.immediate_actions.append(action)
                
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                logger.error(f"Error in action scheduler: {e}")
                time.sleep(10)
    
    def _execute_action(self, action):
        """Execute a response action"""
        try:
            action_type = action.get('action_type', action.get('type'))
            action_id = action.get('id', self._generate_action_id())
            
            logger.info(f"Executing action {action_id}: {action_type}")
            
            success = False
            result = None
            
            if action_type == 'auto_response':
                success, result = self._execute_auto_response_action(action)
            
            elif action_type == 'manual_review':
                success, result = self._execute_manual_review_action(action)
            
            elif action_type == 'notification':
                success, result = self._execute_notification_action(action)
            
            elif action_type == 'block_ip':
                success, result = self._execute_block_action(action)
            
            elif action_type == 'unblock_ip':
                success, result = self._execute_unblock_action(action)
            
            elif action_type == 'custom':
                success, result = self._execute_custom_action(action)
            
            else:
                logger.warning(f"Unknown action type: {action_type}")
                success = False
                result = f"Unknown action type: {action_type}"
            
            # Record action execution
            self._record_action_execution(action, success, result)
            
            if success:
                logger.info(f"Action {action_id} executed successfully")
            else:
                logger.error(f"Action {action_id} failed: {result}")
            
        except Exception as e:
            logger.error(f"Error executing action: {e}")
            self._record_action_execution(action, False, str(e))
    
    def _execute_auto_response_action(self, action):
        """Execute automated response action"""
        try:
            detection_info = action.get('detection_info', {})
            
            # Format threat info for auto response system
            threat_info = {
                'type': detection_info.get('type'),
                'severity': detection_info.get('severity'),
                'src_ip': detection_info.get('src_ip'),
                'dst_ip': detection_info.get('dst_ip'),
                'details': detection_info.get('details', {})
            }
            
            success = self.auto_response.process_threat(threat_info)
            return success, "Auto response executed" if success else "Auto response failed"
            
        except Exception as e:
            return False, str(e)
    
    def _execute_manual_review_action(self, action):
        """Execute manual review submission"""
        try:
            detection_info = action.get('detection_info', {})
            priority = action.get('priority', 'medium')
            
            review_id = self.manual_review.submit_for_review(detection_info, priority)
            
            if review_id:
                return True, f"Submitted for manual review: {review_id}"
            else:
                return False, "Failed to submit for manual review"
                
        except Exception as e:
            return False, str(e)
    
    def _execute_notification_action(self, action):
        """Execute notification action"""
        try:
            detection_info = action.get('detection_info', {})
            methods = action.get('methods', ['email'])
            
            if detection_info:
                self.notification_manager.send_threat_notification(detection_info)
            else:
                message = action.get('message', 'Security event detected')
                self.notification_manager.send_custom_notification(
                    'Security Alert', message, methods
                )
            
            return True, "Notification sent"
            
        except Exception as e:
            return False, str(e)
    
    def _execute_block_action(self, action):
        """Execute IP blocking action"""
        try:
            src_ip = action.get('src_ip')
            if not src_ip:
                detection_info = action.get('detection_info', {})
                src_ip = detection_info.get('src_ip')
            
            if not src_ip:
                return False, "No source IP provided"
            
            duration = action.get('duration', 3600)  # 1 hour default
            
            # Use auto response system for blocking
            threat_info = {
                'type': 'manual_block',
                'severity': 'high',
                'src_ip': src_ip,
                'details': action.get('details', {})
            }
            
            success = self.auto_response._temporary_block(src_ip, duration, threat_info)
            return success, f"Blocked IP {src_ip}" if success else f"Failed to block IP {src_ip}"
            
        except Exception as e:
            return False, str(e)
    
    def _execute_unblock_action(self, action):
        """Execute IP unblocking action"""
        try:
            src_ip = action.get('src_ip')
            if not src_ip:
                return False, "No source IP provided"
            
            success = self.auto_response.unblock_ip_manual(src_ip)
            return success, f"Unblocked IP {src_ip}" if success else f"Failed to unblock IP {src_ip}"
            
        except Exception as e:
            return False, str(e)
    
    def _execute_custom_action(self, action):
        """Execute custom action"""
        try:
            # Custom actions would be implemented based on specific requirements
            custom_type = action.get('custom_type')
            params = action.get('params', {})
            
            logger.info(f"Executing custom action: {custom_type} with params: {params}")
            
            # Placeholder for custom action execution
            return True, f"Custom action {custom_type} executed"
            
        except Exception as e:
            return False, str(e)
    
    def _determine_response_actions(self, detection_info):
        """Determine appropriate response actions based on detection"""
        actions = []
        
        threat_type = detection_info.get('type')
        severity = detection_info.get('severity', 'medium')
        src_ip = detection_info.get('src_ip')
        
        # Check custom policies first
        for policy in self.response_policies:
            if self._policy_matches_detection(policy, detection_info):
                policy_actions = policy.get('actions', [])
                for policy_action in policy_actions:
                    action = self._create_action_from_template(policy_action, detection_info)
                    if action:
                        actions.append(action)
                return actions
        
        # Default response logic based on severity and type
        if severity == 'critical':
            # Immediate blocking and notification
            actions.append(self._create_action_from_template('block_ip', detection_info))
            actions.append(self._create_action_from_template('alert_only', detection_info))
            actions.append(self._create_action_from_template('manual_review', detection_info))
            
        elif severity == 'high':
            # Rate limiting, notification, and manual review
            if threat_type in ['port_scan', 'brute_force']:
                actions.append(self._create_action_from_template('block_ip', detection_info))
            else:
                actions.append(self._create_action_from_template('rate_limit', detection_info))
            
            actions.append(self._create_action_from_template('alert_only', detection_info))
            actions.append(self._create_action_from_template('manual_review', detection_info))
            
        elif severity == 'medium':
            # Rate limiting and notification
            actions.append(self._create_action_from_template('rate_limit', detection_info))
            actions.append(self._create_action_from_template('alert_only', detection_info))
            
        else:  # low severity
            # Just notification
            actions.append(self._create_action_from_template('alert_only', detection_info))
        
        return actions
    
    def _create_action_from_template(self, template_name, detection_info):
        """Create action from template"""
        try:
            if template_name not in self.action_templates:
                logger.warning(f"Unknown action template: {template_name}")
                return None
            
            template = self.action_templates[template_name].copy()
            action = {
                'id': self._generate_action_id(),
                'action_type': template_name,
                'src_ip': detection_info.get('src_ip'),
                'immediate': True,
                **template
            }
            
            return action
            
        except Exception as e:
            logger.error(f"Error creating action from template: {e}")
            return None
    
    def _enrich_detection(self, detection_info):
        """Enrich detection with additional context"""
        enriched = detection_info.copy()
        
        # Add geolocation info (placeholder)
        src_ip = detection_info.get('src_ip')
        if src_ip:
            enriched['geolocation'] = self._get_ip_geolocation(src_ip)
        
        # Add threat intelligence (placeholder)
        enriched['threat_intel'] = self._get_threat_intelligence(src_ip)
        
        # Add historical context
        enriched['historical_activity'] = self._get_historical_activity(src_ip)
        
        return enriched
    
    def _schedule_action(self, action):
        """Schedule an action for future execution"""
        delay = action.get('delay', 0)
        scheduled_time = datetime.now() + timedelta(seconds=delay)
        action['scheduled_time'] = scheduled_time
        
        self.scheduled_actions.append(action)
        logger.info(f"Scheduled action {action.get('id')} for {scheduled_time}")
    
    def _record_action_execution(self, action, success, result):
        """Record action execution in history"""
        record = {
            'action_id': action.get('id'),
            'action_type': action.get('action_type'),
            'detection_id': action.get('detection_id'),
            'timestamp': datetime.now(),
            'success': success,
            'result': result,
            'src_ip': action.get('src_ip')
        }
        
        self.action_history.append(record)
    
    def get_action_statistics(self, hours=24):
        """Get action execution statistics"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        recent_actions = [
            a for a in self.action_history
            if a['timestamp'] > cutoff_time
        ]
        
        stats = {
            'total_actions': len(recent_actions),
            'successful_actions': len([a for a in recent_actions if a['success']]),
            'failed_actions': len([a for a in recent_actions if not a['success']]),
            'by_type': defaultdict(int),
            'pending_actions': len(self.immediate_actions),
            'scheduled_actions': len(self.scheduled_actions)
        }
        
        for action in recent_actions:
            action_type = action.get('action_type', 'unknown')
            stats['by_type'][action_type] += 1
        
        stats['success_rate'] = (
            stats['successful_actions'] / stats['total_actions'] 
            if stats['total_actions'] > 0 else 0
        )
        
        return stats
    
    def get_pending_actions(self):
        """Get list of pending actions"""
        return {
            'immediate': list(self.immediate_actions),
            'scheduled': self.scheduled_actions.copy()
        }
    
    def cancel_action(self, action_id):
        """Cancel a pending action"""
        # Remove from immediate queue
        for action in list(self.immediate_actions):
            if action.get('id') == action_id:
                self.immediate_actions.remove(action)
                logger.info(f"Cancelled immediate action {action_id}")
                return True
        
        # Remove from scheduled queue
        for action in self.scheduled_actions[:]:
            if action.get('id') == action_id:
                self.scheduled_actions.remove(action)
                logger.info(f"Cancelled scheduled action {action_id}")
                return True
        
        return False
    
    def _generate_detection_id(self):
        """Generate unique detection ID"""
        return f"DET_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{id(self) % 10000:04d}"
    
    def _generate_action_id(self):
        """Generate unique action ID"""
        return f"ACT_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{id(self) % 10000:04d}"
    
    def _load_response_policies(self):
        """Load response policies from configuration"""
        try:
            policies_file = config.BASE_DIR / 'config' / 'response_policies.json'
            if policies_file.exists():
                import json
                with open(policies_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error loading response policies: {e}")
        
        return []
    
    def _policy_matches_detection(self, policy, detection_info):
        """Check if policy matches detection"""
        conditions = policy.get('conditions', {})
        
        for field, expected_value in conditions.items():
            if detection_info.get(field) != expected_value:
                return False
        
        return True
    
    def _get_ip_geolocation(self, ip):
        """Get IP geolocation (placeholder)"""
        return {'country': 'Unknown', 'city': 'Unknown'}
    
    def _get_threat_intelligence(self, ip):
        """Get threat intelligence for IP (placeholder)"""
        return {'reputation': 'unknown', 'categories': []}
    
    def _get_historical_activity(self, ip):
        """Get historical activity for IP (placeholder)"""
        return {'previous_detections': 0, 'last_seen': None}

def test_response_framework():
    """Test response action framework"""
    framework = ResponseActionFramework()
    framework.start()
    
    try:
        # Test detection processing
        test_detection = {
            'type': 'port_scan',
            'severity': 'high',
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.1',
            'details': {'ports_scanned': 50}
        }
        
        detection_id = framework.process_detection(test_detection)
        print(f"Processed detection: {detection_id}")
        
        # Wait for processing
        time.sleep(2)
        
        # Get statistics
        stats = framework.get_action_statistics()
        print(f"Action statistics: {stats}")
        
        # Get pending actions
        pending = framework.get_pending_actions()
        print(f"Pending actions: {len(pending['immediate'])} immediate, {len(pending['scheduled'])} scheduled")
        
    finally:
        framework.stop()

if __name__ == "__main__":
    test_response_framework()
