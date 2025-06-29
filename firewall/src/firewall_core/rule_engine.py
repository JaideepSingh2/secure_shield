import ipaddress
import re
import logging
from typing import Dict, List, Any

class RuleEngine:
    def __init__(self, logger):
        self.rules = []
        self.logger = logger
        self.current_profile = "default"
        self.default_action = "ALLOW"  # Default policy: ALLOW or BLOCK
    
    def load_rules(self, rules: List[Dict[str, Any]]):
        """Load rules from the rule manager"""
        self.rules = sorted(rules, key=lambda x: x.get('priority', 0), reverse=True)
        self.logger.log_system_event(f"Loaded {len(rules)} firewall rules")
    
    def set_profile(self, profile: str):
        """Set the current profile"""
        self.current_profile = profile
        self.logger.log_system_event(f"Switched to profile: {profile}")
    
    def set_default_action(self, action: str):
        """Set the default action when no rules match"""
        if action in ["ALLOW", "BLOCK"]:
            self.default_action = action
            self.logger.log_system_event(f"Default action set to: {action}")
        else:
            self.logger.log_system_event(f"Invalid default action: {action}", level=logging.ERROR)
    
    def process_packet(self, packet_info: Dict[str, Any]) -> str:
        """Process a packet against the rules and return the action"""
        for rule in self.rules:
            # Skip rules not in the current profile
            if rule.get('profile') and rule.get('profile') != self.current_profile:
                continue
                
            # Check if rule matches
            if self._rule_matches(rule, packet_info):
                return rule.get('action', self.default_action)
        
        # No rule matched, use default action
        return self.default_action
    
    def _rule_matches(self, rule: Dict[str, Any], packet_info: Dict[str, Any]) -> bool:
        """Check if a packet matches a rule"""
        # Check source IP
        if 'src_ip' in rule and not self._ip_matches(packet_info.get('src_ip', ''), rule['src_ip']):
            return False
            
        # Check destination IP
        if 'dst_ip' in rule and not self._ip_matches(packet_info.get('dst_ip', ''), rule['dst_ip']):
            return False
            
        # Check protocol
        if 'protocol' in rule:
                    rule_proto = rule['protocol'].upper()
                    pkt_proto = packet_info.get('protocol_name', '').upper()
                    if rule_proto != "ANY" and rule_proto != pkt_proto:
                        return False        
                
        # Check source port
        if 'src_port' in rule and not self._port_matches(packet_info.get('src_port', 0), rule['src_port']):
            return False
            
        # Check destination port
        if 'dst_port' in rule and not self._port_matches(packet_info.get('dst_port', 0), rule['dst_port']):
            return False
            
        # All conditions matched
        return True
    
    def _ip_matches(self, ip: str, rule_ip: str) -> bool:
        """Check if an IP matches a rule (supports CIDR, ranges, and single IPs)"""
        try:
            # CIDR notation (e.g., 192.168.1.0/24)
            if '/' in rule_ip:
                network = ipaddress.ip_network(rule_ip)
                return ipaddress.ip_address(ip) in network
                
            # IP range (e.g., 192.168.1.1-192.168.1.10)
            elif '-' in rule_ip:
                start_ip, end_ip = rule_ip.split('-')
                ip_int = int(ipaddress.ip_address(ip))
                start_int = int(ipaddress.ip_address(start_ip))
                end_int = int(ipaddress.ip_address(end_ip))
                return start_int <= ip_int <= end_int
                
            # Single IP
            else:
                return ip == rule_ip
        except Exception as e:
            self.logger.log_system_event(f"Error in IP matching: {str(e)}", level=logging.ERROR)
            return False
    
    def _port_matches(self, port: int, rule_port) -> bool:
        """Check if a port matches a rule (supports ranges and single ports)"""
        try:
            # Port range (e.g., 1000-2000)
            if isinstance(rule_port, str) and '-' in rule_port:
                start_port, end_port = map(int, rule_port.split('-'))
                return start_port <= port <= end_port
                
            # Single port
            else:
                return port == int(rule_port)
        except Exception as e:
            self.logger.log_system_event(f"Error in port matching: {str(e)}", level=logging.ERROR)
            return False