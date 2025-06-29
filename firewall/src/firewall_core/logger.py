import os
import json
import time
import logging
import threading
from typing import Dict, Any, Optional, List

def make_json_safe(obj):
    """Recursively convert non-serializable objects to strings for JSON logging."""
    if isinstance(obj, dict):
        return {k: make_json_safe(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [make_json_safe(i) for i in obj]
    elif hasattr(obj, '__str__') and not isinstance(obj, (str, int, float, bool, type(None))):
        return str(obj)
    else:
        return obj

class FirewallLogger:
    """Log manager for the firewall system"""
    
    def __init__(self, logs_file, python_log_path=None):
        """
        Initialize the FirewallLogger
        
        Args:
            logs_file (str): Path to the JSON logs file
            python_log_path (str): Path to the Python logging file (optional)
        """
        self.logs_file = logs_file
        self.logs = []
        self.processed_count = 0
        self.blocked_count = 0
        self.log_lock = threading.Lock()  # Add a lock for thread safety
        self.in_memory_logs = {"connection_logs": [], "system_events": []}  # In-memory cache

        # Configure Python logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler("firewall.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("FirewallLogger")

        # Set up Python logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Set up file handler with provided path or default
        log_file = python_log_path if python_log_path else "firewall.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)

        # Initialize log file
        if not os.path.exists(self.logs_file):
            with open(self.logs_file, "w") as f:
                json.dump({"connection_logs": [], "system_events": []}, f)
        else:
            # Load existing logs into memory
            try:
                with open(self.logs_file, "r") as f:
                    self.in_memory_logs = json.load(f)
            except Exception as e:
                self.logger.error(f"Failed to load existing logs: {e}")

        # Start background thread to periodically flush logs to disk
        self.flush_thread = threading.Thread(target=self._periodic_flush, daemon=True)
        self.flush_thread.start()

    def _periodic_flush(self):
        """Periodically flush in-memory logs to disk"""
        while True:
            time.sleep(5)  # Flush every 5 seconds
            self._flush_to_disk()

    def _flush_to_disk(self):
        """Flush in-memory logs to disk"""
        try:
            with self.log_lock:
                with open(self.logs_file, "w") as f:
                    json.dump(self.in_memory_logs, f, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
        except Exception as e:
            self.logger.error(f"Error flushing logs to disk: {e}")

    def _read_logs(self):
        """Read logs from memory (no file access during normal operation)"""
        with self.log_lock:
            return {
                "connection_logs": self.in_memory_logs.get("connection_logs", [])[:],
                "system_events": self.in_memory_logs.get("system_events", [])[:]
            }
            
    def _write_logs(self, logs):
        """Update in-memory logs"""
        with self.log_lock:
            self.in_memory_logs = logs
            
    def log_connection(self, packet_info: Dict[str, Any], action: str):
        self.processed_count += 1
        logs = self._read_logs()
        timestamp = packet_info.get('time', time.time())
        src_ip = packet_info.get('src_ip', '')
        dst_ip = packet_info.get('dst_ip', '')
        src_port = packet_info.get('src_port', 0)
        dst_port = packet_info.get('dst_port', 0)
        protocol = packet_info.get('protocol_name', '')
        details_dict = {k: v for k, v in packet_info.items() if k not in ['time', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol_name']}
        details_safe = make_json_safe(details_dict)
        entry = {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "action": action,
            "details": details_safe
        }
        logs["connection_logs"].insert(0, entry)
        logs["connection_logs"] = logs["connection_logs"][:1000]  # Keep last 1000 logs
        self._write_logs(logs)

    def log_blocked_connection(self, packet_info: Dict[str, Any]):
        self.blocked_count += 1
        self.log_connection(packet_info, "BLOCK")
        src = f"{packet_info.get('src_ip', '')}:{packet_info.get('src_port', '')}"
        dst = f"{packet_info.get('dst_ip', '')}:{packet_info.get('dst_port', '')}"
        proto = packet_info.get('protocol_name', '')
        self.logger.warning(f"BLOCKED {proto} connection: {src} -> {dst}")
        if hasattr(self, 'block_callback') and callable(self.block_callback):
            try:
                self.block_callback(packet_info)
            except Exception as e:
                self.logger.error(f"Error in block callback: {str(e)}")

    def log_allowed_connection(self, packet_info: Dict[str, Any]):
        self.log_connection(packet_info, "ALLOW")
        src = f"{packet_info.get('src_ip', '')}:{packet_info.get('src_port', '')}"
        dst = f"{packet_info.get('dst_ip', '')}:{packet_info.get('dst_port', '')}"
        proto = packet_info.get('protocol_name', '')
        self.logger.debug(f"ALLOWED {proto} connection: {src} -> {dst}")

    def log_system_event(self, event: str, level: str = "INFO", details: Optional[Dict[str, Any]] = None):
        level_str = str(level).upper() if level else "INFO"
        if level_str == "ERROR":
            self.logger.error(event)
        elif level_str == "WARNING":
            self.logger.warning(event)
        else:
            self.logger.info(event)
        logs = self._read_logs()
        timestamp = time.time()
        safe_details = make_json_safe(details) if details else None
        entry = {
            "timestamp": timestamp,
            "event": event,
            "level": level_str,
            "details": safe_details
        }
        logs["system_events"].insert(0, entry)
        logs["system_events"] = logs["system_events"][:500]  # Keep last 500 events
        self._write_logs(logs)

    def get_recent_connections(self, limit: int = 100, action: Optional[str] = None) -> List[Dict[str, Any]]:
        logs = self._read_logs()
        conns = logs.get("connection_logs", [])
        if action:
            conns = [c for c in conns if c.get("action") == action]
        return conns[:limit]

    def get_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        logs = self._read_logs()
        return logs.get("system_events", [])[:limit]

    def set_block_callback(self, callback_function):
        self.block_callback = callback_function
        self.logger.info("Block callback registered")

    def get_counts(self):
        return {
            "processed": self.processed_count,
            "blocked": self.blocked_count
        }