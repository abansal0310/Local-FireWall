import threading
import time
import json
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pathlib import Path
import hashlib
import re
from utils.logger import logger
from config.settings import config

class IDSEngine:
    """Intelligent Intrusion Detection System Engine with event correlation and threat intelligence"""
    
    def __init__(self):
        self.events = deque(maxlen=100000)  # Store last 100k events
        self.alerts = deque(maxlen=50000)   # Store last 50k alerts
        self.event_patterns = {}
        self.threat_signatures = {}
        self.correlation_rules = []
        self.baseline_metrics = {}
        self.running = False
        self.engine_lock = threading.Lock()
        
        # Event correlation windows
        self.correlation_windows = {
            'immediate': 60,      # 1 minute
            'short': 300,         # 5 minutes
            'medium': 1800,       # 30 minutes
            'long': 3600          # 1 hour
        }
        
        # Threat intelligence feeds
        self.threat_feeds = {
            'malicious_ips': set(),
            'suspicious_domains': set(),
            'known_signatures': {},
            'attack_patterns': {}
        }
        
        # Attack chain detection
        self.attack_chains = {
            'reconnaissance': ['port_scan', 'dns_enum', 'banner_grab'],
            'exploitation': ['sql_injection', 'code_injection', 'buffer_overflow'],
            'persistence': ['backdoor_install', 'scheduled_task', 'registry_mod'],
            'privilege_escalation': ['local_exploit', 'token_manipulation'],
            'lateral_movement': ['credential_dump', 'remote_access', 'network_share'],
            'exfiltration': ['data_staging', 'compression', 'external_transfer']
        }
        
        # Initialize engine
        self.load_threat_intelligence()
        self.load_correlation_rules()
        self.initialize_baseline()
        
        logger.info("IDSEngine initialized")
    
    def load_threat_intelligence(self):
        """Load threat intelligence data"""
        try:
            intel_file = Path(__file__).parent.parent / "data" / "threat_intelligence.json"
            if intel_file.exists():
                with open(intel_file, 'r') as f:
                    intel_data = json.load(f)
                
                self.threat_feeds['malicious_ips'].update(intel_data.get('malicious_ips', []))
                self.threat_feeds['suspicious_domains'].update(intel_data.get('suspicious_domains', []))
                self.threat_feeds['known_signatures'].update(intel_data.get('signatures', {}))
                self.threat_feeds['attack_patterns'].update(intel_data.get('patterns', {}))
                
                logger.info(f"Loaded threat intelligence: {len(self.threat_feeds['malicious_ips'])} IPs, "
                          f"{len(self.threat_feeds['suspicious_domains'])} domains")
            else:
                # Initialize with default threat intel
                self._initialize_default_threat_intel()
                
        except Exception as e:
            logger.error(f"Error loading threat intelligence: {e}")
            self._initialize_default_threat_intel()
    
    def _initialize_default_threat_intel(self):
        """Initialize with default threat intelligence"""
        # Common malicious IP patterns
        self.threat_feeds['malicious_ips'].update([
            '192.168.1.666',  # Example malicious IP
            '10.0.0.255'      # Example suspicious IP
        ])
        
        # Suspicious domains
        self.threat_feeds['suspicious_domains'].update([
            'malware.example.com',
            'phishing.test.com'
        ])
        
        # Attack signatures
        self.threat_feeds['known_signatures'].update({
            'sql_injection': [
                r"'.*union.*select",
                r"'.*or.*1=1",
                r"'.*drop.*table"
            ],
            'xss_attack': [
                r"<script.*>.*</script>",
                r"javascript:",
                r"onerror.*="
            ],
            'lfi_attack': [
                r"\.\./",
                r"passwd",
                r"etc/shadow"
            ]
        })
    
    def load_correlation_rules(self):
        """Load event correlation rules"""
        try:
            rules_file = Path(__file__).parent.parent / "config" / "correlation_rules.json"
            if rules_file.exists():
                with open(rules_file, 'r') as f:
                    self.correlation_rules = json.load(f)
            else:
                self._initialize_default_correlation_rules()
                
            logger.info(f"Loaded {len(self.correlation_rules)} correlation rules")
            
        except Exception as e:
            logger.error(f"Error loading correlation rules: {e}")
            self._initialize_default_correlation_rules()
    
    def _initialize_default_correlation_rules(self):
        """Initialize default correlation rules"""
        self.correlation_rules = [
            {
                'name': 'Brute Force Detection',
                'conditions': [
                    {'event_type': 'auth_failure', 'count': 5, 'window': 300}
                ],
                'action': 'generate_alert',
                'severity': 'high',
                'description': 'Multiple authentication failures detected'
            },
            {
                'name': 'Port Scan Detection',
                'conditions': [
                    {'event_type': 'port_scan', 'unique_ports': 10, 'window': 60}
                ],
                'action': 'generate_alert',
                'severity': 'medium',
                'description': 'Port scanning activity detected'
            },
            {
                'name': 'DDoS Detection',
                'conditions': [
                    {'event_type': 'flood_detection', 'count': 100, 'window': 60}
                ],
                'action': 'generate_alert',
                'severity': 'critical',
                'description': 'DDoS attack detected'
            },
            {
                'name': 'Attack Chain - Recon to Exploit',
                'conditions': [
                    {'event_type': 'port_scan', 'window': 3600},
                    {'event_type': 'vulnerability_scan', 'window': 1800},
                    {'event_type': 'exploit_attempt', 'window': 600}
                ],
                'action': 'generate_alert',
                'severity': 'critical',
                'description': 'Multi-stage attack detected'
            }
        ]
    
    def initialize_baseline(self):
        """Initialize baseline metrics for anomaly detection"""
        try:
            baseline_file = Path(__file__).parent.parent / "data" / "baseline_metrics.json"
            if baseline_file.exists():
                with open(baseline_file, 'r') as f:
                    self.baseline_metrics = json.load(f)
            else:
                self.baseline_metrics = {
                    'normal_traffic_rate': 100,      # packets per minute
                    'normal_connection_rate': 50,    # connections per minute
                    'normal_error_rate': 0.1,        # error percentage
                    'normal_auth_failures': 2,       # failures per hour
                    'normal_port_scans': 0,          # scans per hour
                    'updated_at': datetime.now().isoformat()
                }
                self.save_baseline()
            
            logger.info("Baseline metrics initialized")
            
        except Exception as e:
            logger.error(f"Error initializing baseline: {e}")
    
    def process_event(self, event):
        """Process a security event through the IDS engine"""
        try:
            with self.engine_lock:
                # Enrich event with additional metadata
                enriched_event = self._enrich_event(event)
                
                # Store event
                self.events.append(enriched_event)
                
                # Perform threat intelligence lookup
                threat_score = self._calculate_threat_score(enriched_event)
                enriched_event['threat_score'] = threat_score
                
                # Check for signature matches
                signature_matches = self._check_signatures(enriched_event)
                if signature_matches:
                    enriched_event['signature_matches'] = signature_matches
                
                # Perform event correlation
                correlation_results = self._correlate_events(enriched_event)
                
                # Check for anomalies
                anomaly_score = self._detect_anomalies(enriched_event)
                enriched_event['anomaly_score'] = anomaly_score
                
                # Generate alerts if necessary
                if (threat_score > 70 or anomaly_score > 80 or 
                    signature_matches or correlation_results):
                    self._generate_alert(enriched_event, correlation_results)
                
                return enriched_event
                
        except Exception as e:
            logger.error(f"Error processing event: {e}")
            return event
    
    def _enrich_event(self, event):
        """Enrich event with additional metadata"""
        enriched = event.copy()
        
        # Add processing timestamp
        enriched['processed_at'] = datetime.now()
        
        # Add unique event ID
        event_hash = hashlib.md5(json.dumps(event, sort_keys=True).encode()).hexdigest()
        enriched['event_id'] = event_hash[:16]
        
        # Add geolocation info (mock implementation)
        source_ip = event.get('source_ip')
        if source_ip:
            enriched['geo_info'] = self._get_geo_info(source_ip)
        
        # Add reputation score
        enriched['reputation_score'] = self._get_reputation_score(event)
        
        # Categorize event
        enriched['category'] = self._categorize_event(event)
        
        return enriched
    
    def _get_geo_info(self, ip_address):
        """Get geolocation information for IP (mock implementation)"""
        # In a real implementation, this would query a GeoIP database
        if ip_address.startswith('192.168.') or ip_address.startswith('10.'):
            return {'country': 'Local', 'region': 'Private', 'risk_level': 'low'}
        elif ip_address in self.threat_feeds['malicious_ips']:
            return {'country': 'Unknown', 'region': 'Unknown', 'risk_level': 'high'}
        else:
            return {'country': 'Unknown', 'region': 'Unknown', 'risk_level': 'medium'}
    
    def _get_reputation_score(self, event):
        """Calculate reputation score for the event source"""
        score = 50  # Neutral score
        
        source_ip = event.get('source_ip')
        if source_ip:
            if source_ip in self.threat_feeds['malicious_ips']:
                score += 40
            elif source_ip.startswith('192.168.') or source_ip.startswith('10.'):
                score -= 10  # Local IPs are generally less risky
        
        event_type = event.get('event_type', '')
        if 'attack' in event_type or 'malicious' in event_type:
            score += 30
        elif 'scan' in event_type:
            score += 20
        
        return min(100, max(0, score))
    
    def _categorize_event(self, event):
        """Categorize the event type"""
        event_type = event.get('event_type', '').lower()
        
        if any(attack in event_type for attack in ['brute_force', 'password', 'auth']):
            return 'authentication'
        elif any(scan in event_type for scan in ['port_scan', 'vulnerability', 'recon']):
            return 'reconnaissance'
        elif any(exploit in event_type for exploit in ['injection', 'overflow', 'exploit']):
            return 'exploitation'
        elif any(dos in event_type for dos in ['flood', 'ddos', 'dos']):
            return 'denial_of_service'
        elif any(malware in event_type for malware in ['malware', 'virus', 'trojan']):
            return 'malware'
        else:
            return 'other'
    
    def _calculate_threat_score(self, event):
        """Calculate threat score based on various factors"""
        score = 0
        
        # Base score from event severity
        severity_scores = {'low': 20, 'medium': 50, 'high': 80, 'critical': 100}
        score += severity_scores.get(event.get('severity', 'low'), 20)
        
        # Threat intelligence score
        source_ip = event.get('source_ip')
        if source_ip and source_ip in self.threat_feeds['malicious_ips']:
            score += 30
        
        # Reputation score contribution
        reputation = event.get('reputation_score', 50)
        if reputation > 70:
            score += 20
        elif reputation < 30:
            score -= 10
        
        # Event frequency boost
        recent_events = self._get_recent_events_from_source(source_ip, 300)
        if len(recent_events) > 5:
            score += 15
        
        # Geolocation risk
        geo_info = event.get('geo_info', {})
        if geo_info.get('risk_level') == 'high':
            score += 25
        
        return min(100, max(0, score))
    
    def _check_signatures(self, event):
        """Check event against known attack signatures"""
        matches = []
        
        payload = event.get('payload', '')
        if not payload:
            return matches
        
        for attack_type, signatures in self.threat_feeds['known_signatures'].items():
            for signature in signatures:
                if re.search(signature, payload, re.IGNORECASE):
                    matches.append({
                        'type': attack_type,
                        'signature': signature,
                        'confidence': 0.8
                    })
        
        return matches
    
    def _correlate_events(self, current_event):
        """Perform event correlation analysis"""
        correlation_results = []
        
        for rule in self.correlation_rules:
            if self._evaluate_correlation_rule(rule, current_event):
                correlation_results.append({
                    'rule_name': rule['name'],
                    'description': rule['description'],
                    'severity': rule['severity'],
                    'matched_conditions': rule['conditions']
                })
        
        # Check for attack chain patterns
        attack_chain_results = self._detect_attack_chains(current_event)
        if attack_chain_results:
            correlation_results.extend(attack_chain_results)
        
        return correlation_results
    
    def _evaluate_correlation_rule(self, rule, current_event):
        """Evaluate if a correlation rule matches"""
        try:
            for condition in rule['conditions']:
                if not self._check_condition(condition, current_event):
                    return False
            return True
            
        except Exception as e:
            logger.error(f"Error evaluating correlation rule {rule['name']}: {e}")
            return False
    
    def _check_condition(self, condition, current_event):
        """Check if a specific condition is met"""
        event_type = condition.get('event_type')
        window = condition.get('window', 300)
        count_threshold = condition.get('count', 1)
        unique_ports = condition.get('unique_ports')
        
        # Get events in the time window
        cutoff_time = datetime.now() - timedelta(seconds=window)
        recent_events = [
            e for e in self.events 
            if e.get('timestamp', datetime.now()) >= cutoff_time
            and e.get('event_type') == event_type
            and e.get('source_ip') == current_event.get('source_ip')
        ]
        
        # Check count condition
        if count_threshold and len(recent_events) < count_threshold:
            return False
        
        # Check unique ports condition
        if unique_ports:
            ports = set()
            for event in recent_events:
                port = event.get('destination_port')
                if port:
                    ports.add(port)
            if len(ports) < unique_ports:
                return False
        
        return True
    
    def _detect_attack_chains(self, current_event):
        """Detect multi-stage attack chains"""
        results = []
        source_ip = current_event.get('source_ip')
        
        if not source_ip:
            return results
        
        # Look for attack chain progression
        for chain_name, stages in self.attack_chains.items():
            detected_stages = []
            
            # Check for each stage in the last 4 hours
            cutoff_time = datetime.now() - timedelta(hours=4)
            
            for stage in stages:
                stage_events = [
                    e for e in self.events
                    if e.get('timestamp', datetime.now()) >= cutoff_time
                    and e.get('source_ip') == source_ip
                    and stage in e.get('event_type', '').lower()
                ]
                
                if stage_events:
                    detected_stages.append({
                        'stage': stage,
                        'events': len(stage_events),
                        'first_seen': min(e.get('timestamp', datetime.now()) for e in stage_events),
                        'last_seen': max(e.get('timestamp', datetime.now()) for e in stage_events)
                    })
            
            # If multiple stages detected, it's likely an attack chain
            if len(detected_stages) >= 2:
                results.append({
                    'rule_name': f'Attack Chain: {chain_name.title()}',
                    'description': f'Multi-stage {chain_name} attack detected from {source_ip}',
                    'severity': 'critical',
                    'detected_stages': detected_stages,
                    'confidence': min(0.9, len(detected_stages) / len(stages))
                })
        
        return results
    
    def _detect_anomalies(self, event):
        """Detect anomalous behavior based on baseline"""
        anomaly_score = 0
        
        # Traffic volume anomaly
        current_rate = self._calculate_current_traffic_rate()
        baseline_rate = self.baseline_metrics.get('normal_traffic_rate', 100)
        
        if current_rate > baseline_rate * 3:
            anomaly_score += 30
        elif current_rate > baseline_rate * 2:
            anomaly_score += 15
        
        # Connection rate anomaly
        current_conn_rate = self._calculate_current_connection_rate()
        baseline_conn_rate = self.baseline_metrics.get('normal_connection_rate', 50)
        
        if current_conn_rate > baseline_conn_rate * 3:
            anomaly_score += 25
        elif current_conn_rate > baseline_conn_rate * 2:
            anomaly_score += 10
        
        # Time-based anomaly (activity during unusual hours)
        current_hour = datetime.now().hour
        if current_hour < 6 or current_hour > 22:  # Outside business hours
            if event.get('category') in ['exploitation', 'reconnaissance']:
                anomaly_score += 20
        
        # Geographic anomaly
        geo_info = event.get('geo_info', {})
        if geo_info.get('country') == 'Unknown':
            anomaly_score += 15
        
        return min(100, anomaly_score)
    
    def _calculate_current_traffic_rate(self):
        """Calculate current traffic rate (events per minute)"""
        cutoff_time = datetime.now() - timedelta(minutes=1)
        recent_events = [
            e for e in self.events
            if e.get('timestamp', datetime.now()) >= cutoff_time
        ]
        return len(recent_events)
    
    def _calculate_current_connection_rate(self):
        """Calculate current connection rate"""
        cutoff_time = datetime.now() - timedelta(minutes=1)
        connections = set()
        
        for event in self.events:
            if event.get('timestamp', datetime.now()) >= cutoff_time:
                source_ip = event.get('source_ip')
                dest_port = event.get('destination_port')
                if source_ip and dest_port:
                    connections.add(f"{source_ip}:{dest_port}")
        
        return len(connections)
    
    def _generate_alert(self, event, correlation_results):
        """Generate security alert"""
        try:
            alert = {
                'alert_id': self._generate_alert_id(),
                'timestamp': datetime.now(),
                'event_id': event.get('event_id'),
                'source_ip': event.get('source_ip'),
                'event_type': event.get('event_type'),
                'severity': self._determine_alert_severity(event, correlation_results),
                'threat_score': event.get('threat_score', 0),
                'anomaly_score': event.get('anomaly_score', 0),
                'description': self._generate_alert_description(event, correlation_results),
                'correlation_results': correlation_results,
                'signature_matches': event.get('signature_matches', []),
                'recommended_actions': self._get_recommended_actions(event, correlation_results)
            }
            
            self.alerts.append(alert)
            
            # Log security event
            logger.security_event("IDS_ALERT", 
                f"Alert {alert['alert_id']}: {alert['description']}", 
                alert['severity'].upper())
            
            return alert
            
        except Exception as e:
            logger.error(f"Error generating alert: {e}")
            return None
    
    def _determine_alert_severity(self, event, correlation_results):
        """Determine alert severity based on various factors"""
        threat_score = event.get('threat_score', 0)
        anomaly_score = event.get('anomaly_score', 0)
        signature_matches = event.get('signature_matches', [])
        
        # Start with event severity
        base_severity = event.get('severity', 'low')
        
        # Upgrade based on scores
        if threat_score > 80 or anomaly_score > 80:
            return 'critical'
        elif threat_score > 60 or anomaly_score > 60:
            return 'high'
        elif signature_matches or correlation_results:
            return 'high'
        elif threat_score > 40 or anomaly_score > 40:
            return 'medium'
        else:
            return base_severity
    
    def _generate_alert_description(self, event, correlation_results):
        """Generate human-readable alert description"""
        base_desc = f"{event.get('event_type', 'Security event')} from {event.get('source_ip', 'unknown source')}"
        
        if correlation_results:
            correlations = ", ".join([r.get('rule_name', 'Unknown') for r in correlation_results])
            base_desc += f" (Correlated with: {correlations})"
        
        signature_matches = event.get('signature_matches', [])
        if signature_matches:
            signatures = ", ".join([m.get('type', 'Unknown') for m in signature_matches])
            base_desc += f" (Signature matches: {signatures})"
        
        return base_desc
    
    def _get_recommended_actions(self, event, correlation_results):
        """Get recommended response actions"""
        actions = []
        
        threat_score = event.get('threat_score', 0)
        severity = self._determine_alert_severity(event, correlation_results)
        
        if threat_score > 80 or severity == 'critical':
            actions.extend([
                'Block source IP immediately',
                'Investigate all recent activity from this source',
                'Check for indicators of compromise',
                'Notify security team'
            ])
        elif threat_score > 60 or severity == 'high':
            actions.extend([
                'Monitor source IP closely',
                'Apply rate limiting',
                'Review logs for additional suspicious activity'
            ])
        else:
            actions.extend([
                'Log for future reference',
                'Monitor for pattern repetition'
            ])
        
        # Add specific actions based on event type
        event_type = event.get('event_type', '').lower()
        if 'brute_force' in event_type:
            actions.append('Implement account lockout policies')
        elif 'port_scan' in event_type:
            actions.append('Check firewall rules for unnecessary open ports')
        elif 'injection' in event_type:
            actions.append('Review and patch vulnerable applications')
        
        return actions
    
    def _get_recent_events_from_source(self, source_ip, seconds):
        """Get recent events from a specific source IP"""
        if not source_ip:
            return []
        
        cutoff_time = datetime.now() - timedelta(seconds=seconds)
        return [
            e for e in self.events
            if e.get('source_ip') == source_ip
            and e.get('timestamp', datetime.now()) >= cutoff_time
        ]
    
    def update_baseline(self):
        """Update baseline metrics based on recent normal activity"""
        try:
            # Calculate new baseline from last 24 hours of non-alert events
            cutoff_time = datetime.now() - timedelta(hours=24)
            
            normal_events = [
                e for e in self.events
                if e.get('timestamp', datetime.now()) >= cutoff_time
                and e.get('threat_score', 0) < 30  # Only consider low-threat events
            ]
            
            if normal_events:
                # Update traffic rate baseline
                hourly_rates = []
                for hour in range(24):
                    hour_start = cutoff_time + timedelta(hours=hour)
                    hour_end = hour_start + timedelta(hours=1)
                    
                    hour_events = [
                        e for e in normal_events
                        if hour_start <= e.get('timestamp', datetime.now()) < hour_end
                    ]
                    hourly_rates.append(len(hour_events))
                
                if hourly_rates:
                    self.baseline_metrics['normal_traffic_rate'] = sum(hourly_rates) / len(hourly_rates)
                
                # Update other baselines
                self.baseline_metrics['updated_at'] = datetime.now().isoformat()
                self.save_baseline()
                
                logger.info("Baseline metrics updated")
            
        except Exception as e:
            logger.error(f"Error updating baseline: {e}")
    
    def save_baseline(self):
        """Save baseline metrics to disk"""
        try:
            baseline_file = Path(__file__).parent.parent / "data" / "baseline_metrics.json"
            baseline_file.parent.mkdir(parents=True, exist_ok=True)
            with open(baseline_file, 'w') as f:
                json.dump(self.baseline_metrics, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error saving baseline: {e}")
    
    def get_statistics(self):
        """Get IDS engine statistics"""
        recent_time = datetime.now() - timedelta(hours=24)
        
        recent_events = [
            e for e in self.events
            if e.get('timestamp', datetime.now()) >= recent_time
        ]
        
        recent_alerts = [
            a for a in self.alerts
            if a.get('timestamp', datetime.now()) >= recent_time
        ]
        
        # Count by severity
        severity_counts = defaultdict(int)
        for alert in recent_alerts:
            severity_counts[alert.get('severity', 'unknown')] += 1
        
        # Count by category
        category_counts = defaultdict(int)
        for event in recent_events:
            category_counts[event.get('category', 'unknown')] += 1
        
        return {
            'total_events': len(self.events),
            'total_alerts': len(self.alerts),
            'events_24h': len(recent_events),
            'alerts_24h': len(recent_alerts),
            'alert_rate': len(recent_alerts) / max(1, len(recent_events)) * 100,
            'severity_breakdown': dict(severity_counts),
            'category_breakdown': dict(category_counts),
            'correlation_rules': len(self.correlation_rules),
            'threat_intel_ips': len(self.threat_feeds['malicious_ips']),
            'baseline_updated': self.baseline_metrics.get('updated_at')
        }
    
    def _generate_alert_id(self):
        """Generate unique alert ID"""
        return f"IDS_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{id(self) % 10000:04d}"

def test_ids_engine():
    """Test IDS engine functionality"""
    ids = IDSEngine()
    
    print("Testing IDSEngine...")
    
    # Test event processing
    test_event = {
        'timestamp': datetime.now(),
        'event_type': 'port_scan',
        'source_ip': '192.168.1.100',
        'destination_port': 80,
        'severity': 'medium',
        'payload': 'GET / HTTP/1.1'
    }
    
    result = ids.process_event(test_event)
    print(f"Processed event: {result.get('event_id')}")
    
    # Test statistics
    stats = ids.get_statistics()
    print(f"IDS Statistics: {stats}")

if __name__ == "__main__":
    test_ids_engine()
