import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
from utils.logger import logger
from config.settings import config

class PortScanDetector:
    """Advanced port scan detection system"""
    
    def __init__(self):
        # Configuration
        self.threshold = config.PORT_SCAN_THRESHOLD
        self.time_window = config.PORT_SCAN_TIME_WINDOW
        
        # Connection tracking
        self.connections = defaultdict(lambda: {
            'ports': set(),
            'timestamps': deque(),
            'tcp_flags': defaultdict(int),
            'first_seen': None,
            'last_seen': None,
            'packet_count': 0
        })
        
        # Scan type patterns
        self.scan_patterns = {
            'tcp_connect': {'SYN': 1, 'SYN,ACK': 1, 'ACK': 1},
            'syn_scan': {'SYN': 1},
            'fin_scan': {'FIN': 1},
            'null_scan': {'': 1},  # No flags
            'xmas_scan': {'FIN,PSH,URG': 1},
            'ack_scan': {'ACK': 1},
            'window_scan': {'ACK': 1},  # Analyzed by window size
            'maimon_scan': {'FIN,ACK': 1}
        }
        
        # Detection results
        self.detected_scans = deque(maxlen=1000)
        
        logger.info("PortScanDetector initialized")
    
    def analyze_packet(self, packet_info):
        """Analyze packet for port scan indicators"""
        if not packet_info or packet_info.get('transport_protocol') != 'tcp':
            return None
        
        src_ip = packet_info.get('src_ip')
        dst_port = packet_info.get('dst_port')
        tcp_flags = packet_info.get('tcp_flags_str', '')
        timestamp = packet_info.get('timestamp', datetime.now())
        
        if not src_ip or not dst_port:
            return None
        
        # Update connection tracking
        conn_data = self.connections[src_ip]
        conn_data['ports'].add(dst_port)
        conn_data['timestamps'].append(timestamp)
        conn_data['tcp_flags'][tcp_flags] += 1
        conn_data['packet_count'] += 1
        
        if not conn_data['first_seen']:
            conn_data['first_seen'] = timestamp
        conn_data['last_seen'] = timestamp
        
        # Clean old timestamps
        self._clean_old_timestamps(src_ip, timestamp)
        
        # Check for scan patterns
        scan_result = self._detect_scan_pattern(src_ip)
        
        if scan_result:
            logger.security_event("PORT_SCAN_DETECTED", 
                f"Port scan detected from {src_ip}: {scan_result['scan_type']} "
                f"({len(conn_data['ports'])} ports in {scan_result['duration']:.1f}s)", 
                "HIGH")
            
            # Store detection result
            self.detected_scans.append({
                'timestamp': timestamp,
                'src_ip': src_ip,
                'scan_type': scan_result['scan_type'],
                'ports_scanned': len(conn_data['ports']),
                'duration': scan_result['duration'],
                'confidence': scan_result['confidence']
            })
            
            return scan_result
        
        return None
    
    def _clean_old_timestamps(self, src_ip, current_time):
        """Remove timestamps older than the time window"""
        conn_data = self.connections[src_ip]
        cutoff_time = current_time - timedelta(seconds=self.time_window)
        
        # Remove old timestamps
        while conn_data['timestamps'] and conn_data['timestamps'][0] < cutoff_time:
            conn_data['timestamps'].popleft()
        
        # If no recent activity, clean up the connection
        if not conn_data['timestamps']:
            # Keep the ports for a bit longer to detect slow scans
            if (current_time - conn_data['last_seen']).seconds > self.time_window * 2:
                del self.connections[src_ip]
    
    def _detect_scan_pattern(self, src_ip):
        """Detect specific scan patterns"""
        conn_data = self.connections[src_ip]
        
        # Check if we have enough ports for a scan
        if len(conn_data['ports']) < self.threshold:
            return None
        
        # Calculate scan duration
        if not conn_data['timestamps']:
            return None
        
        duration = (conn_data['timestamps'][-1] - conn_data['timestamps'][0]).total_seconds()
        
        # Determine scan type based on TCP flags
        scan_type = self._identify_scan_type(conn_data['tcp_flags'])
        
        # Calculate confidence based on various factors
        confidence = self._calculate_confidence(conn_data, duration)
        
        return {
            'scan_type': scan_type,
            'duration': duration,
            'confidence': confidence,
            'ports_count': len(conn_data['ports']),
            'packet_count': conn_data['packet_count']
        }
    
    def _identify_scan_type(self, tcp_flags):
        """Identify scan type based on TCP flags pattern"""
        total_packets = sum(tcp_flags.values())
        
        if total_packets == 0:
            return 'unknown'
        
        # Calculate flag percentages
        flag_percentages = {flag: count/total_packets for flag, count in tcp_flags.items()}
        
        # Identify scan type
        if flag_percentages.get('SYN', 0) > 0.8 and flag_percentages.get('ACK', 0) < 0.1:
            return 'syn_scan'
        elif flag_percentages.get('FIN', 0) > 0.8:
            return 'fin_scan'
        elif flag_percentages.get('ACK', 0) > 0.8:
            return 'ack_scan'
        elif 'FIN,PSH,URG' in tcp_flags:
            return 'xmas_scan'
        elif '' in tcp_flags:  # NULL scan
            return 'null_scan'
        elif 'FIN,ACK' in tcp_flags:
            return 'maimon_scan'
        elif flag_percentages.get('SYN', 0) > 0.3 and flag_percentages.get('SYN,ACK', 0) > 0.1:
            return 'tcp_connect'
        else:
            return 'custom_scan'
    
    def _calculate_confidence(self, conn_data, duration):
        """Calculate confidence score for scan detection"""
        confidence = 0.0
        
        # Port count factor (more ports = higher confidence)
        port_factor = min(len(conn_data['ports']) / 50, 1.0)  # Max at 50 ports
        confidence += port_factor * 0.4
        
        # Speed factor (faster scans are more suspicious)
        if duration > 0:
            ports_per_second = len(conn_data['ports']) / duration
            speed_factor = min(ports_per_second / 10, 1.0)  # Max at 10 ports/sec
            confidence += speed_factor * 0.3
        
        # Pattern consistency (consistent flags indicate intentional scanning)
        if conn_data['tcp_flags']:
            dominant_flag = max(conn_data['tcp_flags'], key=conn_data['tcp_flags'].get)
            pattern_consistency = conn_data['tcp_flags'][dominant_flag] / conn_data['packet_count']
            confidence += pattern_consistency * 0.3
        
        return min(confidence, 1.0)
    
    def is_whitelisted(self, ip_address):
        """Check if IP is whitelisted"""
        # Load whitelist from config
        rules = config.get_rules()
        whitelist = rules.get('whitelist', [])
        return ip_address in whitelist
    
    def get_scan_statistics(self):
        """Get scanning statistics"""
        active_scanners = len(self.connections)
        total_detections = len(self.detected_scans)
        
        # Recent detections (last hour)
        recent_cutoff = datetime.now() - timedelta(hours=1)
        recent_detections = [scan for scan in self.detected_scans 
                           if scan['timestamp'] > recent_cutoff]
        
        # Scan type distribution
        scan_types = defaultdict(int)
        for scan in self.detected_scans:
            scan_types[scan['scan_type']] += 1
        
        return {
            'active_scanners': active_scanners,
            'total_detections': total_detections,
            'recent_detections': len(recent_detections),
            'scan_type_distribution': dict(scan_types),
            'threshold': self.threshold,
            'time_window': self.time_window
        }
    
    def get_top_scanners(self, limit=10):
        """Get top scanning IPs"""
        scanner_stats = defaultdict(lambda: {'count': 0, 'ports': set(), 'last_seen': None})
        
        for scan in self.detected_scans:
            ip = scan['src_ip']
            scanner_stats[ip]['count'] += 1
            scanner_stats[ip]['ports'].update([scan['ports_scanned']])
            if not scanner_stats[ip]['last_seen'] or scan['timestamp'] > scanner_stats[ip]['last_seen']:
                scanner_stats[ip]['last_seen'] = scan['timestamp']
        
        # Convert to list and sort
        top_scanners = []
        for ip, stats in scanner_stats.items():
            top_scanners.append({
                'ip': ip,
                'scan_count': stats['count'],
                'total_ports': sum(stats['ports']),
                'last_seen': stats['last_seen']
            })
        
        top_scanners.sort(key=lambda x: x['scan_count'], reverse=True)
        return top_scanners[:limit]
    
    def cleanup_old_data(self):
        """Clean up old detection data"""
        cutoff_time = datetime.now() - timedelta(hours=24)
        
        # Clean up old detections
        self.detected_scans = deque([
            scan for scan in self.detected_scans 
            if scan['timestamp'] > cutoff_time
        ], maxlen=1000)
        
        # Clean up old connections
        for src_ip in list(self.connections.keys()):
            conn_data = self.connections[src_ip]
            if conn_data['last_seen'] and (datetime.now() - conn_data['last_seen']).seconds > 3600:
                del self.connections[src_ip]

# Test function
    def get_active_scans(self):
        """Get currently active scan attempts"""
        current_time = datetime.now()
        active_scans = []
        
        for src_ip, data in self.connections.items():
            if data['last_seen']:
                time_diff = (current_time - data['last_seen']).total_seconds()
                if time_diff <= self.time_window:
                    active_scans.append({
                        'src_ip': src_ip,
                        'ports_scanned': len(data['ports']),
                        'last_activity': data['last_seen'],
                        'duration': time_diff,
                        'packet_count': data['packet_count']
                    })
        
        return active_scans

def test_port_scan_detector():
    """Test port scan detector functionality"""
    detector = PortScanDetector()
    
    print("Testing PortScanDetector...")
    
    # Simulate a SYN scan
    base_time = datetime.now()
    test_packets = []
    
    for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]):
        packet_info = {
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.1',
            'dst_port': port,
            'transport_protocol': 'tcp',
            'tcp_flags_str': 'SYN',
            'timestamp': base_time + timedelta(seconds=i)
        }
        test_packets.append(packet_info)
    
    # Analyze packets
    for packet in test_packets:
        result = detector.analyze_packet(packet)
        if result:
            print(f"Scan detected: {result}")
    
    # Get statistics
    stats = detector.get_scan_statistics()
    print(f"Statistics: {stats}")
    
    # Get top scanners
    top_scanners = detector.get_top_scanners()
    print(f"Top scanners: {top_scanners}")

if __name__ == "__main__":
    test_port_scan_detector()