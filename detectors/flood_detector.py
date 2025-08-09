import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
from utils.logger import logger
from config.settings import config

class FloodDetector:
    """DDoS and flood attack detection system"""
    
    def __init__(self):
        # Configuration
        self.syn_threshold = config.FLOOD_THRESHOLD
        self.udp_threshold = config.FLOOD_THRESHOLD
        self.icmp_threshold = 50  # Lower threshold for ICMP
        self.time_window = config.FLOOD_TIME_WINDOW
        
        # Traffic tracking by source IP
        self.syn_traffic = defaultdict(lambda: deque())
        self.udp_traffic = defaultdict(lambda: deque())
        self.icmp_traffic = defaultdict(lambda: deque())
        self.http_requests = defaultdict(lambda: deque())
        
        # Global traffic tracking
        self.global_syn_count = deque()
        self.global_udp_count = deque()
        self.global_icmp_count = deque()
        
        # Detection results
        self.detected_floods = deque(maxlen=1000)
        
        # Connection state tracking for SYN flood detection
        self.connection_states = defaultdict(lambda: {'syn_sent': 0, 'established': 0})
        
        logger.info("FloodDetector initialized")
    
    def analyze_packet(self, packet_info):
        """Analyze packet for flood attack indicators"""
        if not packet_info:
            return None
        
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        protocol = packet_info.get('transport_protocol')
        timestamp = packet_info.get('timestamp', datetime.now())
        
        if not src_ip or not protocol:
            return None
        
        detection_result = None
        
        # Analyze based on protocol
        if protocol == 'tcp':
            detection_result = self._analyze_tcp_packet(packet_info, timestamp)
        elif protocol == 'udp':
            detection_result = self._analyze_udp_packet(packet_info, timestamp)
        elif protocol == 'icmp':
            detection_result = self._analyze_icmp_packet(packet_info, timestamp)
        
        # Clean old data periodically
        if int(time.time()) % 30 == 0:  # Every 30 seconds
            self._cleanup_old_data(timestamp)
        
        return detection_result
    
    def _analyze_tcp_packet(self, packet_info, timestamp):
        """Analyze TCP packet for SYN flood and other attacks"""
        src_ip = packet_info.get('src_ip')
        tcp_flags = packet_info.get('tcp_flags_str', '')
        dst_port = packet_info.get('dst_port')
        
        # SYN flood detection
        if 'SYN' in tcp_flags and 'ACK' not in tcp_flags:
            self.syn_traffic[src_ip].append(timestamp)
            self.global_syn_count.append(timestamp)
            self.connection_states[src_ip]['syn_sent'] += 1
            
            # Check for SYN flood from single IP
            if self._check_flood_threshold(self.syn_traffic[src_ip], self.syn_threshold, timestamp):
                return self._create_flood_detection('syn_flood', src_ip, len(self.syn_traffic[src_ip]), timestamp)
            
            # Check for global SYN flood
            if self._check_flood_threshold(self.global_syn_count, self.syn_threshold * 5, timestamp):
                return self._create_flood_detection('global_syn_flood', 'multiple', len(self.global_syn_count), timestamp)
        
        # Track established connections
        elif 'SYN' in tcp_flags and 'ACK' in tcp_flags:
            self.connection_states[src_ip]['established'] += 1
        
        # HTTP flood detection (if targeting web ports)
        if dst_port in [80, 443, 8080, 8443]:
            self.http_requests[src_ip].append(timestamp)
            if self._check_flood_threshold(self.http_requests[src_ip], 50, timestamp):  # 50 requests per window
                return self._create_flood_detection('http_flood', src_ip, len(self.http_requests[src_ip]), timestamp)
        
        return None
    
    def _analyze_udp_packet(self, packet_info, timestamp):
        """Analyze UDP packet for flood attacks"""
        src_ip = packet_info.get('src_ip')
        dst_port = packet_info.get('dst_port')
        packet_size = packet_info.get('size', 0)
        
        self.udp_traffic[src_ip].append((timestamp, packet_size))
        self.global_udp_count.append(timestamp)
        
        # Check for UDP flood from single IP
        if self._check_flood_threshold([t for t, s in self.udp_traffic[src_ip]], self.udp_threshold, timestamp):
            total_bytes = sum(s for t, s in self.udp_traffic[src_ip] if (timestamp - t).seconds <= self.time_window)
            return self._create_flood_detection('udp_flood', src_ip, len(self.udp_traffic[src_ip]), timestamp, total_bytes)
        
        # Check for DNS amplification (large UDP responses to port 53)
        if dst_port == 53 and packet_size > 512:  # DNS responses shouldn't be this large normally
            logger.security_event("DNS_AMPLIFICATION", 
                f"Possible DNS amplification from {src_ip}: {packet_size} bytes", 
                "WARNING")
        
        return None
    
    def _analyze_icmp_packet(self, packet_info, timestamp):
        """Analyze ICMP packet for flood attacks"""
        src_ip = packet_info.get('src_ip')
        icmp_type = packet_info.get('icmp_type')
        
        self.icmp_traffic[src_ip].append(timestamp)
        self.global_icmp_count.append(timestamp)
        
        # Check for ICMP flood from single IP
        if self._check_flood_threshold(self.icmp_traffic[src_ip], self.icmp_threshold, timestamp):
            return self._create_flood_detection('icmp_flood', src_ip, len(self.icmp_traffic[src_ip]), timestamp)
        
        # Check for ping of death (large ICMP packets)
        packet_size = packet_info.get('size', 0)
        if packet_size > 1500:  # Larger than typical MTU
            logger.security_event("ICMP_LARGE_PACKET", 
                f"Large ICMP packet from {src_ip}: {packet_size} bytes", 
                "WARNING")
        
        return None
    
    def _check_flood_threshold(self, traffic_list, threshold, current_time):
        """Check if traffic exceeds flood threshold within time window"""
        cutoff_time = current_time - timedelta(seconds=self.time_window)
        
        # Count recent traffic
        recent_traffic = [t for t in traffic_list if t > cutoff_time]
        
        return len(recent_traffic) >= threshold
    
    def _create_flood_detection(self, flood_type, src_ip, packet_count, timestamp, bytes_count=None):
        """Create flood detection result"""
        detection = {
            'timestamp': timestamp,
            'flood_type': flood_type,
            'src_ip': src_ip,
            'packet_count': packet_count,
            'time_window': self.time_window,
            'severity': self._get_flood_severity(flood_type, packet_count)
        }
        
        if bytes_count:
            detection['bytes_count'] = bytes_count
        
        # Add to detected floods
        self.detected_floods.append(detection)
        
        # Log security event
        severity_level = "CRITICAL" if detection['severity'] == 'high' else "WARNING"
        logger.security_event(f"{flood_type.upper()}_DETECTED", 
            f"{flood_type} detected from {src_ip}: {packet_count} packets in {self.time_window}s", 
            severity_level)
        
        return detection
    
    def _get_flood_severity(self, flood_type, packet_count):
        """Determine flood severity based on type and volume"""
        if flood_type in ['syn_flood', 'global_syn_flood']:
            if packet_count > self.syn_threshold * 5:
                return 'high'
            elif packet_count > self.syn_threshold * 2:
                return 'medium'
            else:
                return 'low'
        elif flood_type == 'udp_flood':
            if packet_count > self.udp_threshold * 3:
                return 'high'
            elif packet_count > self.udp_threshold * 1.5:
                return 'medium'
            else:
                return 'low'
        elif flood_type == 'icmp_flood':
            if packet_count > self.icmp_threshold * 2:
                return 'high'
            else:
                return 'medium'
        else:
            return 'medium'
    
    def _cleanup_old_data(self, current_time):
        """Clean up old traffic data"""
        cutoff_time = current_time - timedelta(seconds=self.time_window * 2)
        
        # Clean SYN traffic
        for ip in list(self.syn_traffic.keys()):
            self.syn_traffic[ip] = deque([t for t in self.syn_traffic[ip] if t > cutoff_time])
            if not self.syn_traffic[ip]:
                del self.syn_traffic[ip]
        
        # Clean UDP traffic
        for ip in list(self.udp_traffic.keys()):
            self.udp_traffic[ip] = deque([(t, s) for t, s in self.udp_traffic[ip] if t > cutoff_time])
            if not self.udp_traffic[ip]:
                del self.udp_traffic[ip]
        
        # Clean ICMP traffic
        for ip in list(self.icmp_traffic.keys()):
            self.icmp_traffic[ip] = deque([t for t in self.icmp_traffic[ip] if t > cutoff_time])
            if not self.icmp_traffic[ip]:
                del self.icmp_traffic[ip]
        
        # Clean HTTP requests
        for ip in list(self.http_requests.keys()):
            self.http_requests[ip] = deque([t for t in self.http_requests[ip] if t > cutoff_time])
            if not self.http_requests[ip]:
                del self.http_requests[ip]
        
        # Clean global counters
        self.global_syn_count = deque([t for t in self.global_syn_count if t > cutoff_time])
        self.global_udp_count = deque([t for t in self.global_udp_count if t > cutoff_time])
        self.global_icmp_count = deque([t for t in self.global_icmp_count if t > cutoff_time])
    
    def get_flood_statistics(self):
        """Get flood detection statistics"""
        total_detections = len(self.detected_floods)
        
        # Recent detections (last hour)
        recent_cutoff = datetime.now() - timedelta(hours=1)
        recent_detections = [flood for flood in self.detected_floods 
                           if flood['timestamp'] > recent_cutoff]
        
        # Flood type distribution
        flood_types = defaultdict(int)
        severity_distribution = defaultdict(int)
        
        for flood in self.detected_floods:
            flood_types[flood['flood_type']] += 1
            severity_distribution[flood['severity']] += 1
        
        return {
            'total_detections': total_detections,
            'recent_detections': len(recent_detections),
            'flood_type_distribution': dict(flood_types),
            'severity_distribution': dict(severity_distribution),
            'active_sources': {
                'syn_sources': len(self.syn_traffic),
                'udp_sources': len(self.udp_traffic),
                'icmp_sources': len(self.icmp_traffic),
                'http_sources': len(self.http_requests)
            },
            'thresholds': {
                'syn_threshold': self.syn_threshold,
                'udp_threshold': self.udp_threshold,
                'icmp_threshold': self.icmp_threshold,
                'time_window': self.time_window
            }
        }
    
    def get_top_flood_sources(self, limit=10):
        """Get top flood attack sources"""
        source_stats = defaultdict(lambda: {'total_floods': 0, 'flood_types': set(), 'last_seen': None})
        
        for flood in self.detected_floods:
            ip = flood['src_ip']
            source_stats[ip]['total_floods'] += 1
            source_stats[ip]['flood_types'].add(flood['flood_type'])
            if not source_stats[ip]['last_seen'] or flood['timestamp'] > source_stats[ip]['last_seen']:
                source_stats[ip]['last_seen'] = flood['timestamp']
        
        # Convert to list and sort
        top_sources = []
        for ip, stats in source_stats.items():
            top_sources.append({
                'ip': ip,
                'total_floods': stats['total_floods'],
                'flood_types': list(stats['flood_types']),
                'last_seen': stats['last_seen']
            })
        
        top_sources.sort(key=lambda x: x['total_floods'], reverse=True)
        return top_sources[:limit]
    
    def get_connection_ratio_analysis(self):
        """Analyze SYN to established connection ratios for anomaly detection"""
        analysis = {}
        
        for ip, states in self.connection_states.items():
            syn_count = states['syn_sent']
            established_count = states['established']
            
            if syn_count > 0:
                ratio = established_count / syn_count
                analysis[ip] = {
                    'syn_sent': syn_count,
                    'established': established_count,
                    'completion_ratio': ratio,
                    'suspicious': ratio < 0.1 and syn_count > 20  # Low completion rate with high SYN count
                }
        
        return analysis

# Test function
    def get_active_floods(self):
        """Get currently active flood attacks"""
        current_time = datetime.now()
        active_floods = []
        
        # Check recent detections
        cutoff_time = current_time - timedelta(seconds=self.time_window)
        
        for detection in self.detected_floods:
            if detection['timestamp'] >= cutoff_time:
                active_floods.append(detection)
        
        return active_floods
    
    def cleanup_old_data(self):
        """Clean up old traffic data"""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.time_window * 2)
        
        # Clean up TCP connections
        for src_ip in list(self.tcp_connections.keys()):
            self.tcp_connections[src_ip] = deque([
                ts for ts in self.tcp_connections[src_ip] 
                if ts >= cutoff_time
            ], maxlen=1000)
            if not self.tcp_connections[src_ip]:
                del self.tcp_connections[src_ip]
        
        # Clean up UDP connections  
        for src_ip in list(self.udp_connections.keys()):
            self.udp_connections[src_ip] = deque([
                ts for ts in self.udp_connections[src_ip]
                if ts >= cutoff_time
            ], maxlen=1000)
            if not self.udp_connections[src_ip]:
                del self.udp_connections[src_ip]
        
        # Clean up ICMP traffic
        for src_ip in list(self.icmp_traffic.keys()):
            self.icmp_traffic[src_ip] = deque([
                ts for ts in self.icmp_traffic[src_ip]
                if ts >= cutoff_time
            ], maxlen=1000)
            if not self.icmp_traffic[src_ip]:
                del self.icmp_traffic[src_ip]
        
        # Clean up global SYN tracking
        self.global_syn_packets = deque([
            ts for ts in self.global_syn_packets
            if ts >= cutoff_time
        ], maxlen=10000)

def test_flood_detector():
    """Test flood detector functionality"""
    detector = FloodDetector()
    
    print("Testing FloodDetector...")
    
    # Simulate SYN flood
    base_time = datetime.now()
    
    # Generate flood packets
    for i in range(150):  # Above threshold
        packet_info = {
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.1',
            'dst_port': 80,
            'transport_protocol': 'tcp',
            'tcp_flags_str': 'SYN',
            'timestamp': base_time + timedelta(milliseconds=i*50),
            'size': 60
        }
        
        result = detector.analyze_packet(packet_info)
        if result:
            print(f"Flood detected: {result}")
    
    # Test UDP flood
    for i in range(120):  # Above threshold
        packet_info = {
            'src_ip': '192.168.1.101',
            'dst_ip': '192.168.1.1',
            'dst_port': 1234,
            'transport_protocol': 'udp',
            'timestamp': base_time + timedelta(milliseconds=i*60),
            'size': 1024
        }
        
        result = detector.analyze_packet(packet_info)
        if result:
            print(f"UDP flood detected: {result}")
    
    # Get statistics
    stats = detector.get_flood_statistics()
    print(f"Flood statistics: {stats}")
    
    # Get top sources
    top_sources = detector.get_top_flood_sources()
    print(f"Top flood sources: {top_sources}")
    
    # Connection analysis
    conn_analysis = detector.get_connection_ratio_analysis()
    print(f"Connection analysis: {conn_analysis}")

if __name__ == "__main__":
    test_flood_detector()