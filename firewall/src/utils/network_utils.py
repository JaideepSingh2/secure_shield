import socket
import netifaces
import psutil
import subprocess
from typing import Dict, List, Tuple, Any

class NetworkUtils:
    @staticmethod
    def get_ip_addresses() -> Dict[str, str]:
        """Get all IP addresses of this machine"""
        ip_addresses = {}
        
        try:
            interfaces = netifaces.interfaces()
            for interface in interfaces:
                addresses = netifaces.ifaddresses(interface)
                
                # Get IPv4 addresses
                if netifaces.AF_INET in addresses:
                    ip_addresses[interface] = addresses[netifaces.AF_INET][0]['addr']
        except Exception as e:
            print(f"Error getting IP addresses: {e}")
        
        return ip_addresses
    
    @staticmethod
    def get_open_ports() -> List[Dict[str, Any]]:
        """Get list of open ports and associated processes"""
        open_ports = []
        
        try:
            # Get all network connections
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                # Skip connections without PIDs
                if conn.pid is None:
                    continue
                
                try:
                    # Get process info
                    process = psutil.Process(conn.pid)
                    
                    # Add port info to the list
                    port_info = {
                        'local_port': conn.laddr.port if conn.laddr else None,
                        'remote_port': conn.raddr.port if conn.raddr else None,
                        'local_address': conn.laddr.ip if conn.laddr else None,
                        'remote_address': conn.raddr.ip if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid,
                        'process_name': process.name(),
                        'protocol': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                    }
                    
                    open_ports.append(port_info)
                except psutil.NoSuchProcess:
                    # Process might have terminated
                    continue
        except Exception as e:
            print(f"Error getting open ports: {e}")
        
        return open_ports
    
    @staticmethod
    def check_port(port: int, protocol: str = 'tcp') -> bool:
        """Check if a specific port is open"""
        try:
            if protocol.lower() == 'tcp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                return result == 0
            elif protocol.lower() == 'udp':
                # UDP port checking is more complex and less reliable
                return any(conn.laddr.port == port for conn in psutil.net_connections(kind='udp'))
        except:
            return False
        
        return False
    
    @staticmethod
    def get_active_connections() -> List[Dict[str, Any]]:
        """Get a list of active network connections"""
        connections = []
        
        try:
            # Get all TCP connections
            tcp_connections = psutil.net_connections(kind='tcp')
            for conn in tcp_connections:
                if conn.status == 'ESTABLISHED':
                    try:
                        process_name = psutil.Process(conn.pid).name() if conn.pid else "Unknown"
                    except:
                        process_name = "Unknown"
                        
                    connections.append({
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                        'status': conn.status,
                        'process_name': process_name,
                        'protocol': 'TCP'
                    })
        except Exception as e:
            print(f"Error getting active connections: {e}")
        
        return connections
    
    @staticmethod
    def get_network_stats() -> Dict[str, Any]:
        """Get network usage statistics"""
        try:
            # Get total bytes sent/received
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
        except Exception as e:
            print(f"Error getting network stats: {e}")
            return {}
    
    @staticmethod
    def resolve_hostname(ip_address: str) -> str:
        """Resolve an IP address to hostname"""
        try:
            return socket.gethostbyaddr(ip_address)[0]
        except:
            return ip_address