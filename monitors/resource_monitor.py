import threading
import time
import psutil
from datetime import datetime, timedelta
from collections import deque
from utils.logger import logger
from config.settings import config

class ResourceMonitor:
    """System resource monitoring for security anomalies"""
    
    def __init__(self, check_interval=5):
        self.running = False
        self.check_interval = check_interval
        self.monitor_thread = None
        
        # Resource thresholds (configurable)
        self.cpu_threshold = 85.0      # CPU usage %
        self.memory_threshold = 90.0   # Memory usage %
        self.disk_threshold = 95.0     # Disk usage %
        self.network_threshold = 100   # MB/s
        
        # Historical data
        self.cpu_history = deque(maxlen=720)      # 1 hour at 5s intervals
        self.memory_history = deque(maxlen=720)
        self.network_history = deque(maxlen=720)
        self.disk_history = deque(maxlen=720)
        
        # Baseline values for anomaly detection
        self.baseline_cpu = 0.0
        self.baseline_memory = 0.0
        self.baseline_network = 0.0
        
        # Alert tracking
        self.last_cpu_alert = None
        self.last_memory_alert = None
        self.last_network_alert = None
        self.alert_cooldown = 300  # 5 minutes
        
        logger.info("ResourceMonitor initialized")
    
    def start_monitoring(self):
        """Start resource monitoring"""
        if self.running:
            logger.warning("Resource monitoring already running")
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Resource monitoring started")
    
    def stop_monitoring(self):
        """Stop resource monitoring"""
        self.running = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        logger.info("Resource monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        try:
            while self.running:
                timestamp = datetime.now()
                
                # Collect metrics
                cpu_percent = self._get_cpu_usage()
                memory_percent = self._get_memory_usage()
                network_stats = self._get_network_usage()
                disk_usage = self._get_disk_usage()
                
                # Store historical data
                self.cpu_history.append((timestamp, cpu_percent))
                self.memory_history.append((timestamp, memory_percent))
                self.network_history.append((timestamp, network_stats))
                self.disk_history.append((timestamp, disk_usage))
                
                # Check for anomalies
                self._check_cpu_anomaly(cpu_percent, timestamp)
                self._check_memory_anomaly(memory_percent, timestamp)
                self._check_network_anomaly(network_stats, timestamp)
                self._check_disk_anomaly(disk_usage, timestamp)
                
                # Update baselines periodically
                if len(self.cpu_history) > 60:  # After 5 minutes
                    self._update_baselines()
                
                time.sleep(self.check_interval)
                
        except Exception as e:
            logger.error(f"Error in resource monitoring loop: {e}")
    
    def _get_cpu_usage(self):
        """Get current CPU usage percentage"""
        return psutil.cpu_percent(interval=1)
    
    def _get_memory_usage(self):
        """Get current memory usage percentage"""
        memory = psutil.virtual_memory()
        return memory.percent
    
    def _get_network_usage(self):
        """Get current network usage statistics"""
        net_io = psutil.net_io_counters()
        return {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
            'errin': net_io.errin,
            'errout': net_io.errout,
            'dropin': net_io.dropin,
            'dropout': net_io.dropout
        }
    
    def _get_disk_usage(self):
        """Get disk usage statistics"""
        disk_usage = {}
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_usage[partition.device] = {
                    'total': usage.total,
                    'used': usage.used,
                    'free': usage.free,
                    'percent': (usage.used / usage.total) * 100 if usage.total > 0 else 0
                }
            except PermissionError:
                continue
        return disk_usage
    
    def _check_cpu_anomaly(self, cpu_percent, timestamp):
        """Check for CPU usage anomalies"""
        if cpu_percent > self.cpu_threshold:
            if not self.last_cpu_alert or (timestamp - self.last_cpu_alert).seconds > self.alert_cooldown:
                logger.security_event("HIGH_CPU_USAGE", 
                    f"High CPU usage detected: {cpu_percent:.1f}%", 
                    "WARNING")
                self.last_cpu_alert = timestamp
                
                # Get top processes
                top_processes = self._get_top_processes_by_cpu()
                logger.warning(f"Top CPU processes: {top_processes}")
    
    def _check_memory_anomaly(self, memory_percent, timestamp):
        """Check for memory usage anomalies"""
        if memory_percent > self.memory_threshold:
            if not self.last_memory_alert or (timestamp - self.last_memory_alert).seconds > self.alert_cooldown:
                logger.security_event("HIGH_MEMORY_USAGE", 
                    f"High memory usage detected: {memory_percent:.1f}%", 
                    "WARNING")
                self.last_memory_alert = timestamp
                
                # Get top processes
                top_processes = self._get_top_processes_by_memory()
                logger.warning(f"Top memory processes: {top_processes}")
    
    def _check_network_anomaly(self, network_stats, timestamp):
        """Check for network usage anomalies"""
        if len(self.network_history) < 2:
            return
        
        # Calculate network rate
        prev_timestamp, prev_stats = self.network_history[-2]
        time_diff = (timestamp - prev_timestamp).total_seconds()
        
        if time_diff > 0:
            bytes_per_sec = (network_stats['bytes_sent'] + network_stats['bytes_recv'] - 
                           prev_stats['bytes_sent'] - prev_stats['bytes_recv']) / time_diff
            mb_per_sec = bytes_per_sec / (1024 * 1024)
            
            if mb_per_sec > self.network_threshold:
                if not self.last_network_alert or (timestamp - self.last_network_alert).seconds > self.alert_cooldown:
                    logger.security_event("HIGH_NETWORK_USAGE", 
                        f"High network usage detected: {mb_per_sec:.1f} MB/s", 
                        "WARNING")
                    self.last_network_alert = timestamp
            
            # Check for unusual error rates
            error_rate = network_stats['errin'] + network_stats['errout']
            if error_rate > 100:  # More than 100 errors
                logger.security_event("NETWORK_ERRORS", 
                    f"High network error rate: {error_rate} errors", 
                    "WARNING")
    
    def _check_disk_anomaly(self, disk_usage, timestamp):
        """Check for disk usage anomalies"""
        for device, usage in disk_usage.items():
            if usage['percent'] > self.disk_threshold:
                logger.security_event("HIGH_DISK_USAGE", 
                    f"High disk usage on {device}: {usage['percent']:.1f}%", 
                    "ERROR")
    
    def _get_top_processes_by_cpu(self, limit=5):
        """Get top processes by CPU usage"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort by CPU usage and return top processes
        processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
        return processes[:limit]
    
    def _get_top_processes_by_memory(self, limit=5):
        """Get top processes by memory usage"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort by memory usage and return top processes
        processes.sort(key=lambda x: x['memory_percent'] or 0, reverse=True)
        return processes[:limit]
    
    def _update_baselines(self):
        """Update baseline values for anomaly detection"""
        if len(self.cpu_history) >= 60:
            recent_cpu = [data[1] for data in list(self.cpu_history)[-60:]]
            self.baseline_cpu = sum(recent_cpu) / len(recent_cpu)
        
        if len(self.memory_history) >= 60:
            recent_memory = [data[1] for data in list(self.memory_history)[-60:]]
            self.baseline_memory = sum(recent_memory) / len(recent_memory)
    
    def get_current_stats(self):
        """Get current system statistics"""
        return {
            'cpu_percent': self._get_cpu_usage(),
            'memory_percent': self._get_memory_usage(),
            'network_stats': self._get_network_usage(),
            'disk_usage': self._get_disk_usage(),
            'load_average': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None,
            'boot_time': datetime.fromtimestamp(psutil.boot_time()),
            'uptime_seconds': time.time() - psutil.boot_time()
        }
    
    def get_statistics(self):
        """Get monitoring statistics"""
        return {
            'running': self.running,
            'check_interval': self.check_interval,
            'cpu_threshold': self.cpu_threshold,
            'memory_threshold': self.memory_threshold,
            'network_threshold': self.network_threshold,
            'disk_threshold': self.disk_threshold,
            'baseline_cpu': self.baseline_cpu,
            'baseline_memory': self.baseline_memory,
            'history_size': {
                'cpu': len(self.cpu_history),
                'memory': len(self.memory_history),
                'network': len(self.network_history),
                'disk': len(self.disk_history)
            }
        }
    
    def get_resource_trends(self, hours=1):
        """Get resource usage trends"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Filter recent data
        recent_cpu = [(ts, val) for ts, val in self.cpu_history if ts > cutoff_time]
        recent_memory = [(ts, val) for ts, val in self.memory_history if ts > cutoff_time]
        
        if not recent_cpu or not recent_memory:
            return None
        
        # Calculate trends
        cpu_values = [val for _, val in recent_cpu]
        memory_values = [val for _, val in recent_memory]
        
        return {
            'cpu': {
                'min': min(cpu_values),
                'max': max(cpu_values),
                'avg': sum(cpu_values) / len(cpu_values),
                'current': cpu_values[-1] if cpu_values else 0
            },
            'memory': {
                'min': min(memory_values),
                'max': max(memory_values),
                'avg': sum(memory_values) / len(memory_values),
                'current': memory_values[-1] if memory_values else 0
            }
        }

# Test function
def test_resource_monitor():
    """Test resource monitor functionality"""
    monitor = ResourceMonitor(check_interval=2)
    
    print("Testing ResourceMonitor...")
    
    # Get current stats
    current_stats = monitor.get_current_stats()
    print(f"Current CPU: {current_stats['cpu_percent']:.1f}%")
    print(f"Current Memory: {current_stats['memory_percent']:.1f}%")
    
    # Start monitoring for a short time
    print("Starting monitoring for 10 seconds...")
    monitor.start_monitoring()
    time.sleep(10)
    monitor.stop_monitoring()
    
    # Get statistics
    stats = monitor.get_statistics()
    print(f"Monitoring statistics: {stats}")
    
    # Get trends
    trends = monitor.get_resource_trends()
    if trends:
        print(f"CPU trend: {trends['cpu']}")
        print(f"Memory trend: {trends['memory']}")

if __name__ == "__main__":
    test_resource_monitor()