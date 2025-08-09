import sqlite3
import json
import threading
from datetime import datetime, timedelta
from pathlib import Path
from contextlib import contextmanager
from utils.logger import logger
from config.settings import config

class DatabaseManager:
    """Database management system for the Firewall IDS system"""
    
    def __init__(self, db_path=None):
        self.db_path = db_path or Path(__file__).parent.parent / "data" / "firewall_ids.db"
        self.connection_pool = {}
        self.pool_lock = threading.Lock()
        self.max_connections = 10
        
        # Ensure data directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self.initialize_database()
        
        logger.info(f"DatabaseManager initialized with database: {self.db_path}")
    
    def initialize_database(self):
        """Initialize database tables and indexes"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Create events table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT UNIQUE NOT NULL,
                        timestamp DATETIME NOT NULL,
                        event_type TEXT NOT NULL,
                        source_ip TEXT,
                        destination_ip TEXT,
                        source_port INTEGER,
                        destination_port INTEGER,
                        protocol TEXT,
                        severity TEXT NOT NULL,
                        category TEXT,
                        description TEXT,
                        payload TEXT,
                        threat_score INTEGER DEFAULT 0,
                        anomaly_score INTEGER DEFAULT 0,
                        reputation_score INTEGER DEFAULT 50,
                        geo_country TEXT,
                        geo_region TEXT,
                        signature_matches TEXT,  -- JSON
                        raw_data TEXT,  -- JSON
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create alerts table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        alert_id TEXT UNIQUE NOT NULL,
                        event_id TEXT,
                        timestamp DATETIME NOT NULL,
                        severity TEXT NOT NULL,
                        alert_type TEXT,
                        source_ip TEXT,
                        description TEXT NOT NULL,
                        threat_score INTEGER DEFAULT 0,
                        anomaly_score INTEGER DEFAULT 0,
                        correlation_results TEXT,  -- JSON
                        signature_matches TEXT,   -- JSON
                        recommended_actions TEXT, -- JSON
                        status TEXT DEFAULT 'open',
                        assigned_to TEXT,
                        resolution TEXT,
                        resolved_at DATETIME,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (event_id) REFERENCES events (event_id)
                    )
                ''')
                
                # Create firewall_rules table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS firewall_rules (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        rule_id TEXT UNIQUE NOT NULL,
                        rule_type TEXT NOT NULL,
                        action TEXT NOT NULL,
                        source_ip TEXT,
                        destination_ip TEXT,
                        source_port TEXT,
                        destination_port TEXT,
                        protocol TEXT,
                        priority TEXT DEFAULT 'medium',
                        description TEXT,
                        enabled BOOLEAN DEFAULT 1,
                        temporary BOOLEAN DEFAULT 0,
                        expires_at DATETIME,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create blocked_ips table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS blocked_ips (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip_address TEXT UNIQUE NOT NULL,
                        reason TEXT,
                        blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        expires_at DATETIME,
                        block_count INTEGER DEFAULT 1,
                        last_seen DATETIME,
                        threat_level TEXT DEFAULT 'medium',
                        auto_blocked BOOLEAN DEFAULT 0
                    )
                ''')
                
                # Create threat_intelligence table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS threat_intelligence (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        indicator_type TEXT NOT NULL,
                        indicator_value TEXT NOT NULL,
                        threat_type TEXT,
                        confidence REAL DEFAULT 0.5,
                        source TEXT,
                        description TEXT,
                        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                        active BOOLEAN DEFAULT 1
                    )
                ''')
                
                # Create system_metrics table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS system_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME NOT NULL,
                        metric_name TEXT NOT NULL,
                        metric_value REAL NOT NULL,
                        metric_unit TEXT,
                        component TEXT,
                        metadata TEXT  -- JSON
                    )
                ''')
                
                # Create audit_log table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        user_id TEXT,
                        action TEXT NOT NULL,
                        resource_type TEXT,
                        resource_id TEXT,
                        old_values TEXT,  -- JSON
                        new_values TEXT,  -- JSON
                        ip_address TEXT,
                        user_agent TEXT,
                        success BOOLEAN DEFAULT 1,
                        error_message TEXT
                    )
                ''')
                
                # Create notification_log table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS notification_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        notification_type TEXT NOT NULL,
                        recipient TEXT NOT NULL,
                        subject TEXT,
                        message TEXT,
                        channel TEXT,
                        status TEXT DEFAULT 'pending',
                        error_message TEXT,
                        sent_at DATETIME,
                        alert_id TEXT,
                        FOREIGN KEY (alert_id) REFERENCES alerts (alert_id)
                    )
                ''')
                
                # Create indexes for performance
                self._create_indexes(cursor)
                
                conn.commit()
                logger.info("Database tables initialized successfully")
                
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
            raise
    
    def _create_indexes(self, cursor):
        """Create database indexes for performance"""
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events (source_ip)",
            "CREATE INDEX IF NOT EXISTS idx_events_event_type ON events (event_type)",
            "CREATE INDEX IF NOT EXISTS idx_events_severity ON events (severity)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status)",
            "CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips (ip_address)",
            "CREATE INDEX IF NOT EXISTS idx_blocked_ips_expires ON blocked_ips (expires_at)",
            "CREATE INDEX IF NOT EXISTS idx_firewall_rules_enabled ON firewall_rules (enabled)",
            "CREATE INDEX IF NOT EXISTS idx_threat_intel_indicator ON threat_intelligence (indicator_value)",
            "CREATE INDEX IF NOT EXISTS idx_system_metrics_timestamp ON system_metrics (timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log (timestamp)"
        ]
        
        for index_sql in indexes:
            try:
                cursor.execute(index_sql)
            except Exception as e:
                logger.warning(f"Error creating index: {e}")
    
    @contextmanager
    def get_connection(self):
        """Get database connection with automatic cleanup"""
        thread_id = threading.get_ident()
        
        try:
            with self.pool_lock:
                if thread_id not in self.connection_pool:
                    conn = sqlite3.connect(str(self.db_path), timeout=30.0)
                    conn.row_factory = sqlite3.Row  # Enable dict-like access
                    conn.execute("PRAGMA foreign_keys = ON")
                    conn.execute("PRAGMA journal_mode = WAL")  # Better concurrency
                    self.connection_pool[thread_id] = conn
                
                conn = self.connection_pool[thread_id]
            
            yield conn
            
        except Exception as e:
            logger.error(f"Database error: {e}")
            # Try to rollback on error
            try:
                conn.rollback()
            except:
                pass
            raise
    
    def close_connections(self):
        """Close all database connections"""
        with self.pool_lock:
            for conn in self.connection_pool.values():
                try:
                    conn.close()
                except:
                    pass
            self.connection_pool.clear()
    
    # Event management methods
    def insert_event(self, event_data):
        """Insert a new security event"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Prepare data
                signature_matches = json.dumps(event_data.get('signature_matches', []))
                raw_data = json.dumps(event_data.get('raw_data', {}))
                geo_info = event_data.get('geo_info', {})
                
                cursor.execute('''
                    INSERT INTO events (
                        event_id, timestamp, event_type, source_ip, destination_ip,
                        source_port, destination_port, protocol, severity, category,
                        description, payload, threat_score, anomaly_score, reputation_score,
                        geo_country, geo_region, signature_matches, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event_data.get('event_id'),
                    event_data.get('timestamp'),
                    event_data.get('event_type'),
                    event_data.get('source_ip'),
                    event_data.get('destination_ip'),
                    event_data.get('source_port'),
                    event_data.get('destination_port'),
                    event_data.get('protocol'),
                    event_data.get('severity'),
                    event_data.get('category'),
                    event_data.get('description'),
                    event_data.get('payload'),
                    event_data.get('threat_score', 0),
                    event_data.get('anomaly_score', 0),
                    event_data.get('reputation_score', 50),
                    geo_info.get('country'),
                    geo_info.get('region'),
                    signature_matches,
                    raw_data
                ))
                
                conn.commit()
                return cursor.lastrowid
                
        except Exception as e:
            logger.error(f"Error inserting event: {e}")
            return None
    
    def get_events(self, limit=1000, offset=0, filters=None):
        """Get events with optional filtering"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                query = "SELECT * FROM events"
                params = []
                
                if filters:
                    conditions = []
                    
                    if filters.get('start_time'):
                        conditions.append("timestamp >= ?")
                        params.append(filters['start_time'])
                    
                    if filters.get('end_time'):
                        conditions.append("timestamp <= ?")
                        params.append(filters['end_time'])
                    
                    if filters.get('event_type'):
                        conditions.append("event_type = ?")
                        params.append(filters['event_type'])
                    
                    if filters.get('source_ip'):
                        conditions.append("source_ip = ?")
                        params.append(filters['source_ip'])
                    
                    if filters.get('severity'):
                        conditions.append("severity = ?")
                        params.append(filters['severity'])
                    
                    if filters.get('min_threat_score'):
                        conditions.append("threat_score >= ?")
                        params.append(filters['min_threat_score'])
                    
                    if conditions:
                        query += " WHERE " + " AND ".join(conditions)
                
                query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
                
                # Convert to dictionaries and parse JSON fields
                events = []
                for row in rows:
                    event = dict(row)
                    if event['signature_matches']:
                        event['signature_matches'] = json.loads(event['signature_matches'])
                    if event['raw_data']:
                        event['raw_data'] = json.loads(event['raw_data'])
                    events.append(event)
                
                return events
                
        except Exception as e:
            logger.error(f"Error getting events: {e}")
            return []
    
    def get_event_statistics(self, time_range='24h'):
        """Get event statistics for a time range"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Calculate time cutoff
                if time_range == '1h':
                    cutoff = datetime.now() - timedelta(hours=1)
                elif time_range == '24h':
                    cutoff = datetime.now() - timedelta(hours=24)
                elif time_range == '7d':
                    cutoff = datetime.now() - timedelta(days=7)
                elif time_range == '30d':
                    cutoff = datetime.now() - timedelta(days=30)
                else:
                    cutoff = datetime.now() - timedelta(hours=24)
                
                # Total events
                cursor.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ?", (cutoff,))
                total_events = cursor.fetchone()[0]
                
                # Events by severity
                cursor.execute('''
                    SELECT severity, COUNT(*) 
                    FROM events 
                    WHERE timestamp >= ? 
                    GROUP BY severity
                ''', (cutoff,))
                severity_counts = dict(cursor.fetchall())
                
                # Events by type
                cursor.execute('''
                    SELECT event_type, COUNT(*) 
                    FROM events 
                    WHERE timestamp >= ? 
                    GROUP BY event_type 
                    ORDER BY COUNT(*) DESC 
                    LIMIT 10
                ''', (cutoff,))
                type_counts = dict(cursor.fetchall())
                
                # Top source IPs
                cursor.execute('''
                    SELECT source_ip, COUNT(*) 
                    FROM events 
                    WHERE timestamp >= ? AND source_ip IS NOT NULL 
                    GROUP BY source_ip 
                    ORDER BY COUNT(*) DESC 
                    LIMIT 10
                ''', (cutoff,))
                top_ips = dict(cursor.fetchall())
                
                return {
                    'total_events': total_events,
                    'severity_breakdown': severity_counts,
                    'type_breakdown': type_counts,
                    'top_source_ips': top_ips,
                    'time_range': time_range
                }
                
        except Exception as e:
            logger.error(f"Error getting event statistics: {e}")
            return {}
    
    # Alert management methods
    def insert_alert(self, alert_data):
        """Insert a new alert"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Prepare JSON data
                correlation_results = json.dumps(alert_data.get('correlation_results', []))
                signature_matches = json.dumps(alert_data.get('signature_matches', []))
                recommended_actions = json.dumps(alert_data.get('recommended_actions', []))
                
                cursor.execute('''
                    INSERT INTO alerts (
                        alert_id, event_id, timestamp, severity, alert_type,
                        source_ip, description, threat_score, anomaly_score,
                        correlation_results, signature_matches, recommended_actions,
                        status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    alert_data.get('alert_id'),
                    alert_data.get('event_id'),
                    alert_data.get('timestamp'),
                    alert_data.get('severity'),
                    alert_data.get('alert_type'),
                    alert_data.get('source_ip'),
                    alert_data.get('description'),
                    alert_data.get('threat_score', 0),
                    alert_data.get('anomaly_score', 0),
                    correlation_results,
                    signature_matches,
                    recommended_actions,
                    alert_data.get('status', 'open')
                ))
                
                conn.commit()
                return cursor.lastrowid
                
        except Exception as e:
            logger.error(f"Error inserting alert: {e}")
            return None
    
    def update_alert_status(self, alert_id, status, assigned_to=None, resolution=None):
        """Update alert status"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                update_fields = ["status = ?"]
                params = [status]
                
                if assigned_to:
                    update_fields.append("assigned_to = ?")
                    params.append(assigned_to)
                
                if resolution:
                    update_fields.append("resolution = ?")
                    params.append(resolution)
                
                if status in ['resolved', 'closed']:
                    update_fields.append("resolved_at = ?")
                    params.append(datetime.now())
                
                params.append(alert_id)
                
                cursor.execute(f'''
                    UPDATE alerts 
                    SET {", ".join(update_fields)}
                    WHERE alert_id = ?
                ''', params)
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            logger.error(f"Error updating alert status: {e}")
            return False
    
    def get_alerts(self, limit=1000, offset=0, filters=None):
        """Get alerts with optional filtering"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                query = "SELECT * FROM alerts"
                params = []
                
                if filters:
                    conditions = []
                    
                    if filters.get('status'):
                        conditions.append("status = ?")
                        params.append(filters['status'])
                    
                    if filters.get('severity'):
                        conditions.append("severity = ?")
                        params.append(filters['severity'])
                    
                    if filters.get('start_time'):
                        conditions.append("timestamp >= ?")
                        params.append(filters['start_time'])
                    
                    if filters.get('assigned_to'):
                        conditions.append("assigned_to = ?")
                        params.append(filters['assigned_to'])
                    
                    if conditions:
                        query += " WHERE " + " AND ".join(conditions)
                
                query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
                
                # Convert to dictionaries and parse JSON fields
                alerts = []
                for row in rows:
                    alert = dict(row)
                    if alert['correlation_results']:
                        alert['correlation_results'] = json.loads(alert['correlation_results'])
                    if alert['signature_matches']:
                        alert['signature_matches'] = json.loads(alert['signature_matches'])
                    if alert['recommended_actions']:
                        alert['recommended_actions'] = json.loads(alert['recommended_actions'])
                    alerts.append(alert)
                
                return alerts
                
        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
            return []
    
    # Firewall rule management
    def insert_firewall_rule(self, rule_data):
        """Insert firewall rule"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO firewall_rules (
                        rule_id, rule_type, action, source_ip, destination_ip,
                        source_port, destination_port, protocol, priority,
                        description, enabled, temporary, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    rule_data.get('rule_id'),
                    rule_data.get('rule_type'),
                    rule_data.get('action'),
                    rule_data.get('source_ip'),
                    rule_data.get('destination_ip'),
                    rule_data.get('source_port'),
                    rule_data.get('destination_port'),
                    rule_data.get('protocol'),
                    rule_data.get('priority'),
                    rule_data.get('description'),
                    rule_data.get('enabled', True),
                    rule_data.get('temporary', False),
                    rule_data.get('expires_at')
                ))
                
                conn.commit()
                return cursor.lastrowid
                
        except Exception as e:
            logger.error(f"Error inserting firewall rule: {e}")
            return None
    
    def get_firewall_rules(self, enabled_only=True):
        """Get firewall rules"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                query = "SELECT * FROM firewall_rules"
                params = []
                
                if enabled_only:
                    query += " WHERE enabled = 1"
                
                query += " ORDER BY priority, created_at"
                
                cursor.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"Error getting firewall rules: {e}")
            return []
    
    # Blocked IP management
    def insert_blocked_ip(self, ip_data):
        """Insert blocked IP"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO blocked_ips (
                        ip_address, reason, expires_at, threat_level, auto_blocked
                    ) VALUES (?, ?, ?, ?, ?)
                ''', (
                    ip_data.get('ip_address'),
                    ip_data.get('reason'),
                    ip_data.get('expires_at'),
                    ip_data.get('threat_level'),
                    ip_data.get('auto_blocked', False)
                ))
                
                conn.commit()
                return cursor.lastrowid
                
        except Exception as e:
            logger.error(f"Error inserting blocked IP: {e}")
            return None
    
    def remove_blocked_ip(self, ip_address):
        """Remove blocked IP"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip_address,))
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            logger.error(f"Error removing blocked IP: {e}")
            return False
    
    def get_blocked_ips(self, active_only=True):
        """Get blocked IPs"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                query = "SELECT * FROM blocked_ips"
                
                if active_only:
                    query += " WHERE expires_at IS NULL OR expires_at > ?"
                    cursor.execute(query + " ORDER BY blocked_at DESC", (datetime.now(),))
                else:
                    cursor.execute(query + " ORDER BY blocked_at DESC")
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"Error getting blocked IPs: {e}")
            return []
    
    # System metrics
    def insert_metric(self, metric_data):
        """Insert system metric"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                metadata = json.dumps(metric_data.get('metadata', {}))
                
                cursor.execute('''
                    INSERT INTO system_metrics (
                        timestamp, metric_name, metric_value, metric_unit, 
                        component, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    metric_data.get('timestamp'),
                    metric_data.get('metric_name'),
                    metric_data.get('metric_value'),
                    metric_data.get('metric_unit'),
                    metric_data.get('component'),
                    metadata
                ))
                
                conn.commit()
                return cursor.lastrowid
                
        except Exception as e:
            logger.error(f"Error inserting metric: {e}")
            return None
    
    def cleanup_old_data(self, retention_days=90):
        """Clean up old data based on retention policy"""
        try:
            cutoff_date = datetime.now() - timedelta(days=retention_days)
            
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Clean up old events
                cursor.execute("DELETE FROM events WHERE timestamp < ?", (cutoff_date,))
                events_deleted = cursor.rowcount
                
                # Clean up resolved alerts older than retention
                cursor.execute('''
                    DELETE FROM alerts 
                    WHERE timestamp < ? AND status IN ('resolved', 'closed')
                ''', (cutoff_date,))
                alerts_deleted = cursor.rowcount
                
                # Clean up old metrics
                cursor.execute("DELETE FROM system_metrics WHERE timestamp < ?", (cutoff_date,))
                metrics_deleted = cursor.rowcount
                
                # Clean up expired blocked IPs
                cursor.execute('''
                    DELETE FROM blocked_ips 
                    WHERE expires_at IS NOT NULL AND expires_at < ?
                ''', (datetime.now(),))
                blocked_ips_cleaned = cursor.rowcount
                
                conn.commit()
                
                logger.info(f"Cleanup completed: {events_deleted} events, {alerts_deleted} alerts, "
                          f"{metrics_deleted} metrics, {blocked_ips_cleaned} expired blocks removed")
                
                return {
                    'events_deleted': events_deleted,
                    'alerts_deleted': alerts_deleted,
                    'metrics_deleted': metrics_deleted,
                    'blocked_ips_cleaned': blocked_ips_cleaned
                }
                
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            return None
    
    def get_database_stats(self):
        """Get database statistics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                stats = {}
                
                # Table row counts
                tables = ['events', 'alerts', 'firewall_rules', 'blocked_ips', 
                         'threat_intelligence', 'system_metrics', 'audit_log']
                
                for table in tables:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    stats[f"{table}_count"] = cursor.fetchone()[0]
                
                # Database file size
                stats['db_size_bytes'] = self.db_path.stat().st_size if self.db_path.exists() else 0
                stats['db_size_mb'] = round(stats['db_size_bytes'] / (1024 * 1024), 2)
                
                return stats
                
        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
            return {}

def test_database_manager():
    """Test database manager functionality"""
    # Use a test database
    test_db_path = Path("test_firewall_ids.db")
    db = DatabaseManager(test_db_path)
    
    print("Testing DatabaseManager...")
    
    # Test event insertion
    test_event = {
        'event_id': 'TEST_001',
        'timestamp': datetime.now(),
        'event_type': 'port_scan',
        'source_ip': '192.168.1.100',
        'severity': 'medium',
        'threat_score': 60
    }
    
    event_id = db.insert_event(test_event)
    print(f"Inserted event with ID: {event_id}")
    
    # Test getting events
    events = db.get_events(limit=10)
    print(f"Retrieved {len(events)} events")
    
    # Test database stats
    stats = db.get_database_stats()
    print(f"Database stats: {stats}")
    
    # Cleanup
    db.close_connections()
    if test_db_path.exists():
        test_db_path.unlink()

if __name__ == "__main__":
    test_database_manager()
