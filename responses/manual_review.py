import json
import threading
from datetime import datetime, timedelta
from collections import deque
from pathlib import Path
from utils.logger import logger
from config.settings import config

class ManualReviewInterface:
    """Manual review interface for security analysts"""
    
    def __init__(self):
        self.pending_reviews = deque(maxlen=1000)
        self.reviewed_items = deque(maxlen=5000)
        self.escalated_items = deque(maxlen=1000)
        self.review_queue_lock = threading.Lock()
        
        # Review categories
        self.review_categories = {
            'false_positive': 'Confirmed false positive',
            'true_positive': 'Confirmed threat',
            'needs_escalation': 'Requires escalation',
            'insufficient_data': 'Need more information',
            'whitelist_candidate': 'Consider for whitelist'
        }
        
        # Auto-review rules
        self.auto_review_rules = self._load_auto_review_rules()
        
        logger.info("ManualReviewInterface initialized")
    
    def submit_for_review(self, detection_info, priority='medium'):
        """Submit a detection for manual review"""
        try:
            review_item = {
                'id': self._generate_review_id(),
                'timestamp': datetime.now(),
                'detection_info': detection_info,
                'priority': priority,
                'status': 'pending',
                'assigned_to': None,
                'notes': [],
                'automated_analysis': self._perform_automated_analysis(detection_info)
            }
            
            # Check if this should be auto-reviewed
            auto_decision = self._check_auto_review(detection_info)
            if auto_decision:
                review_item['status'] = 'auto_reviewed'
                review_item['decision'] = auto_decision
                review_item['reviewed_at'] = datetime.now()
                review_item['reviewed_by'] = 'auto_system'
                self.reviewed_items.append(review_item)
                logger.info(f"Auto-reviewed item {review_item['id']}: {auto_decision}")
                return review_item['id']
            
            with self.review_queue_lock:
                self.pending_reviews.append(review_item)
            
            logger.info(f"Submitted detection for manual review: {review_item['id']}")
            return review_item['id']
            
        except Exception as e:
            logger.error(f"Error submitting for review: {e}")
            return None
    
    def get_pending_reviews(self, priority_filter=None, limit=50):
        """Get pending reviews, optionally filtered by priority"""
        with self.review_queue_lock:
            reviews = list(self.pending_reviews)
        
        if priority_filter:
            reviews = [r for r in reviews if r['priority'] == priority_filter]
        
        # Sort by priority and timestamp
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        reviews.sort(key=lambda x: (
            priority_order.get(x['priority'], 4),
            x['timestamp']
        ))
        
        return reviews[:limit]
    
    def assign_review(self, review_id, analyst_id):
        """Assign a review to an analyst"""
        try:
            with self.review_queue_lock:
                for review in self.pending_reviews:
                    if review['id'] == review_id:
                        review['assigned_to'] = analyst_id
                        review['assigned_at'] = datetime.now()
                        logger.info(f"Assigned review {review_id} to {analyst_id}")
                        return True
            return False
        except Exception as e:
            logger.error(f"Error assigning review: {e}")
            return False
    
    def add_review_note(self, review_id, analyst_id, note):
        """Add a note to a review"""
        try:
            note_entry = {
                'timestamp': datetime.now(),
                'analyst_id': analyst_id,
                'note': note
            }
            
            with self.review_queue_lock:
                for review in self.pending_reviews:
                    if review['id'] == review_id:
                        review['notes'].append(note_entry)
                        logger.info(f"Added note to review {review_id}")
                        return True
            return False
        except Exception as e:
            logger.error(f"Error adding review note: {e}")
            return False
    
    def complete_review(self, review_id, analyst_id, decision, confidence, notes=None):
        """Complete a manual review"""
        try:
            if decision not in self.review_categories:
                logger.error(f"Invalid review decision: {decision}")
                return False
            
            with self.review_queue_lock:
                review_item = None
                for i, review in enumerate(self.pending_reviews):
                    if review['id'] == review_id:
                        review_item = review
                        del self.pending_reviews[i]
                        break
                
                if not review_item:
                    logger.error(f"Review {review_id} not found")
                    return False
                
                # Complete the review
                review_item.update({
                    'status': 'completed',
                    'decision': decision,
                    'confidence': confidence,
                    'reviewed_by': analyst_id,
                    'reviewed_at': datetime.now(),
                    'final_notes': notes
                })
                
                # Handle escalation
                if decision == 'needs_escalation':
                    self.escalated_items.append(review_item)
                    logger.security_event("REVIEW_ESCALATED", 
                        f"Review {review_id} escalated by {analyst_id}", 
                        "WARNING")
                else:
                    self.reviewed_items.append(review_item)
                
                logger.info(f"Completed review {review_id}: {decision} (confidence: {confidence})")
                
                # Execute follow-up actions
                self._execute_review_actions(review_item)
                
                return True
                
        except Exception as e:
            logger.error(f"Error completing review: {e}")
            return False
    
    def get_review_details(self, review_id):
        """Get detailed information about a specific review"""
        # Check pending reviews
        with self.review_queue_lock:
            for review in self.pending_reviews:
                if review['id'] == review_id:
                    return review
        
        # Check completed reviews
        for review in self.reviewed_items:
            if review['id'] == review_id:
                return review
        
        # Check escalated items
        for review in self.escalated_items:
            if review['id'] == review_id:
                return review
        
        return None
    
    def get_analyst_workload(self, analyst_id):
        """Get workload statistics for an analyst"""
        current_assignments = 0
        completed_today = 0
        today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        
        with self.review_queue_lock:
            for review in self.pending_reviews:
                if review.get('assigned_to') == analyst_id:
                    current_assignments += 1
        
        for review in self.reviewed_items:
            if (review.get('reviewed_by') == analyst_id and 
                review.get('reviewed_at', datetime.min) >= today_start):
                completed_today += 1
        
        return {
            'current_assignments': current_assignments,
            'completed_today': completed_today,
            'total_pending': len(self.pending_reviews),
            'analyst_id': analyst_id
        }
    
    def get_review_statistics(self, days=7):
        """Get review statistics for the specified number of days"""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        stats = {
            'total_reviews': 0,
            'completed_reviews': 0,
            'pending_reviews': len(self.pending_reviews),
            'escalated_reviews': len(self.escalated_items),
            'auto_reviewed': 0,
            'decisions': {category: 0 for category in self.review_categories},
            'average_review_time': 0,
            'by_priority': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'by_analyst': {}
        }
        
        review_times = []
        
        for review in self.reviewed_items:
            if review['timestamp'] >= cutoff_date:
                stats['total_reviews'] += 1
                stats['completed_reviews'] += 1
                
                decision = review.get('decision', 'unknown')
                if decision in stats['decisions']:
                    stats['decisions'][decision] += 1
                
                priority = review.get('priority', 'medium')
                if priority in stats['by_priority']:
                    stats['by_priority'][priority] += 1
                
                analyst = review.get('reviewed_by', 'unknown')
                if analyst != 'auto_system':
                    stats['by_analyst'][analyst] = stats['by_analyst'].get(analyst, 0) + 1
                else:
                    stats['auto_reviewed'] += 1
                
                # Calculate review time
                if review.get('reviewed_at') and review.get('timestamp'):
                    review_time = (review['reviewed_at'] - review['timestamp']).total_seconds()
                    review_times.append(review_time)
        
        # Calculate average review time
        if review_times:
            stats['average_review_time'] = sum(review_times) / len(review_times)
        
        with self.review_queue_lock:
            for review in self.pending_reviews:
                if review['timestamp'] >= cutoff_date:
                    stats['total_reviews'] += 1
                    priority = review.get('priority', 'medium')
                    if priority in stats['by_priority']:
                        stats['by_priority'][priority] += 1
        
        return stats
    
    def _perform_automated_analysis(self, detection_info):
        """Perform automated analysis to assist manual review"""
        analysis = {
            'risk_score': 0,
            'indicators': [],
            'recommendations': [],
            'similar_detections': 0
        }
        
        try:
            # Calculate risk score based on various factors
            src_ip = detection_info.get('src_ip')
            threat_type = detection_info.get('type')
            severity = detection_info.get('severity', 'medium')
            
            # Base risk score from severity
            severity_scores = {'low': 1, 'medium': 3, 'high': 6, 'critical': 10}
            analysis['risk_score'] = severity_scores.get(severity, 3)
            
            # Check for known bad IPs
            if self._is_known_bad_ip(src_ip):
                analysis['risk_score'] += 5
                analysis['indicators'].append('Source IP in threat intelligence feeds')
            
            # Check geolocation
            if self._is_suspicious_geolocation(src_ip):
                analysis['risk_score'] += 2
                analysis['indicators'].append('Suspicious geolocation')
            
            # Check for similar recent detections
            similar_count = self._count_similar_detections(detection_info)
            analysis['similar_detections'] = similar_count
            if similar_count > 5:
                analysis['risk_score'] += 3
                analysis['indicators'].append(f'{similar_count} similar detections in last 24h')
            
            # Generate recommendations
            analysis['recommendations'] = self._generate_recommendations(detection_info, analysis)
            
        except Exception as e:
            logger.error(f"Error in automated analysis: {e}")
        
        return analysis
    
    def _check_auto_review(self, detection_info):
        """Check if detection can be auto-reviewed"""
        for rule in self.auto_review_rules:
            if self._rule_matches_detection(rule, detection_info):
                return rule['decision']
        return None
    
    def _execute_review_actions(self, review_item):
        """Execute actions based on review decision"""
        try:
            decision = review_item['decision']
            detection_info = review_item['detection_info']
            
            if decision == 'false_positive':
                # Add to false positive database
                self._record_false_positive(detection_info)
                
            elif decision == 'whitelist_candidate':
                # Add to whitelist consideration
                self._consider_for_whitelist(detection_info)
                
            elif decision == 'true_positive':
                # Trigger additional response actions
                self._handle_confirmed_threat(detection_info)
            
        except Exception as e:
            logger.error(f"Error executing review actions: {e}")
    
    def _generate_review_id(self):
        """Generate unique review ID"""
        return f"REV_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{id(self) % 10000:04d}"
    
    def _load_auto_review_rules(self):
        """Load auto-review rules from configuration"""
        try:
            rules_file = config.BASE_DIR / 'config' / 'auto_review_rules.json'
            if rules_file.exists():
                with open(rules_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error loading auto-review rules: {e}")
        
        # Default rules
        return [
            {
                'name': 'Low severity internal traffic',
                'conditions': {
                    'severity': 'low',
                    'src_ip_internal': True
                },
                'decision': 'false_positive'
            }
        ]
    
    def _rule_matches_detection(self, rule, detection_info):
        """Check if auto-review rule matches detection"""
        conditions = rule.get('conditions', {})
        
        for field, expected_value in conditions.items():
            if field == 'src_ip_internal':
                src_ip = detection_info.get('src_ip', '')
                is_internal = src_ip.startswith(('192.168.', '10.', '172.'))
                if is_internal != expected_value:
                    return False
            else:
                if detection_info.get(field) != expected_value:
                    return False
        
        return True
    
    def _is_known_bad_ip(self, src_ip):
        """Check if IP is in threat intelligence feeds"""
        # Placeholder - would integrate with real threat intel
        return False
    
    def _is_suspicious_geolocation(self, src_ip):
        """Check if IP geolocation is suspicious"""
        # Placeholder - would integrate with geolocation service
        return False
    
    def _count_similar_detections(self, detection_info):
        """Count similar detections in recent history"""
        # Placeholder - would check detection history
        return 0
    
    def _generate_recommendations(self, detection_info, analysis):
        """Generate action recommendations"""
        recommendations = []
        
        if analysis['risk_score'] >= 8:
            recommendations.append('Consider immediate blocking')
        elif analysis['risk_score'] >= 5:
            recommendations.append('Monitor closely for additional activity')
        else:
            recommendations.append('Standard monitoring sufficient')
        
        return recommendations
    
    def _record_false_positive(self, detection_info):
        """Record false positive for future reference"""
        try:
            fp_file = config.DATA_DIR / 'false_positives.json'
            fps = []
            
            if fp_file.exists():
                with open(fp_file, 'r') as f:
                    fps = json.load(f)
            
            fps.append({
                'timestamp': datetime.now().isoformat(),
                'detection_info': detection_info
            })
            
            with open(fp_file, 'w') as f:
                json.dump(fps, f, indent=2)
                
        except Exception as e:
            logger.error(f"Error recording false positive: {e}")
    
    def _consider_for_whitelist(self, detection_info):
        """Consider adding source to whitelist"""
        logger.info(f"Considering {detection_info.get('src_ip')} for whitelist")
    
    def _handle_confirmed_threat(self, detection_info):
        """Handle confirmed threat detection"""
        logger.security_event("THREAT_CONFIRMED", 
            f"Threat confirmed by manual review: {detection_info}", 
            "ERROR")

def test_manual_review():
    """Test manual review interface"""
    review_interface = ManualReviewInterface()
    
    # Test submitting for review
    test_detection = {
        'type': 'port_scan',
        'severity': 'medium',
        'src_ip': '192.168.1.100',
        'timestamp': datetime.now()
    }
    
    review_id = review_interface.submit_for_review(test_detection, 'high')
    print(f"Submitted review: {review_id}")
    
    # Test getting pending reviews
    pending = review_interface.get_pending_reviews()
    print(f"Pending reviews: {len(pending)}")
    
    # Test assigning review
    review_interface.assign_review(review_id, 'analyst1')
    
    # Test completing review
    review_interface.complete_review(review_id, 'analyst1', 'true_positive', 0.9)
    
    # Test statistics
    stats = review_interface.get_review_statistics()
    print(f"Review statistics: {stats}")

if __name__ == "__main__":
    test_manual_review()
