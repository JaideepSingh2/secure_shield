import os
import platform
import subprocess
import threading
import time
from typing import Dict, Any, Optional

class FirewallController:
    def __init__(self, rule_engine, packet_sniffer, logger):
        self.rule_engine = rule_engine
        self.packet_sniffer = packet_sniffer
        self.logger = logger
        self.is_running = False
        self.os_type = platform.system().lower()
        self.rules_applied = False
        
    def start(self):
        """Start the firewall"""
        if self.is_running:
            self.logger.log_system_event("Firewall already running")
            return False
        
        try:
            # Start the packet sniffer
            if self.packet_sniffer.start():
                # Apply OS-specific firewall rules if needed
                self._apply_os_firewall_rules()
                
                self.is_running = True
                self.logger.log_system_event("Firewall started")
                return True
            else:
                self.logger.log_system_event("Failed to start packet sniffer", "ERROR")
                return False
                
        except Exception as e:
            self.logger.log_system_event(f"Error starting firewall: {str(e)}", "ERROR")
            return False
    
    def stop(self):
        """Stop the firewall"""
        if not self.is_running:
            self.logger.log_system_event("Firewall already stopped")
            return False
        
        try:
            # Stop packet sniffer
            if self.packet_sniffer.stop():
                # Remove OS-specific firewall rules if needed
                self._remove_os_firewall_rules()
                
                self.is_running = False
                self.logger.log_system_event("Firewall stopped")
                return True
            else:
                self.logger.log_system_event("Failed to stop packet sniffer", "ERROR")
                return False
                
        except Exception as e:
            self.logger.log_system_event(f"Error stopping firewall: {str(e)}", "ERROR")
            return False
    
    def restart(self):
        """Restart the firewall"""
        self.stop()
        time.sleep(1)  # Small delay to ensure cleanup
        return self.start()
    
    def status(self) -> Dict[str, Any]:
        """Get the current status of the firewall"""
        return {
            "running": self.is_running,
            "os": self.os_type,
            "rules_applied": self.rules_applied,
            "profile": self.rule_engine.current_profile,
            "default_action": self.rule_engine.default_action
        }
    
    def _apply_os_firewall_rules(self):
        """Apply firewall rules at the OS level"""
        if self.os_type == "linux":
            try:
                # Check if iptables is available
                iptables_available = self._check_command_exists('iptables')
                if not iptables_available:
                    self.logger.log_system_event("iptables command not found. OS-level firewall rules will not be applied.", "WARNING")
                    self.rules_applied = False
                    return
                    
                # Ensure we have the queue number used by packet_interceptor
                queue_num = self.packet_sniffer.queue_num
                    
                # Flush existing rules
                subprocess.run(["iptables", "-F"], check=True)
                
                # Set default policy to ACCEPT initially
                subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"], check=True)
                subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], check=True)
                
                # Allow loopback traffic
                subprocess.run(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], check=True)
                subprocess.run(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"], check=True)
                
                # Allow established connections
                subprocess.run(["iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], check=True)
                
                # Redirect packets to our NFQueue for processing
                subprocess.run(["iptables", "-A", "INPUT", "-j", "NFQUEUE", "--queue-num", str(queue_num)], check=True)
                subprocess.run(["iptables", "-A", "OUTPUT", "-j", "NFQUEUE", "--queue-num", str(queue_num)], check=True)
                
                self.rules_applied = True
                self.logger.log_system_event(f"Applied OS-level firewall rules with queue {queue_num}")
            except Exception as e:
                self.logger.log_system_event(f"Error applying OS firewall rules: {str(e)}", "ERROR")
                self.rules_applied = False

    def _remove_os_firewall_rules(self):
        """Remove OS firewall rules when stopping"""
        if self.os_type == "linux":
            try:
                # Check if iptables is available
                iptables_available = self._check_command_exists('iptables')
                if not iptables_available:
                    self.logger.log_system_event("iptables command not found. No OS-level firewall rules to remove.", "WARNING")
                    self.rules_applied = False
                    return
                    
                # Flush existing rules
                subprocess.run(["iptables", "-F"], check=True)
                
                # Set default policies to ACCEPT
                subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"], check=True)
                subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"], check=True)
                
                self.rules_applied = False
                self.logger.log_system_event("Removed OS-level firewall rules")
            except Exception as e:
                self.logger.log_system_event(f"Error removing OS firewall rules: {str(e)}", "ERROR")
        
        # Handle other OS types here as needed

    def _check_command_exists(self, command):
        """Check if a command exists in the system PATH"""
        try:
            # Use 'which' command on Unix/Linux or 'where' on Windows
            if self.os_type == "windows":
                subprocess.run(["where", command], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            else:
                subprocess.run(["which", command], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except subprocess.CalledProcessError:
            return False