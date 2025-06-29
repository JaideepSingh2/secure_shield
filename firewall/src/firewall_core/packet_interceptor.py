import threading
import time
import logging
from scapy.all import IP, TCP, UDP, ICMP
import netfilterqueue
import socket

class PacketInterceptor:
    """Intercepts and processes packets using NFQueue"""
    
    def __init__(self, rule_engine, logger):
        self.rule_engine = rule_engine
        self.logger = logger
        self.running = False
        self.nfqueue = None
        self.interceptor_thread = None
        self.queue_num = 1  # NFQueue number
        
    def start(self):
        """Start intercepting packets"""
        if self.running:
            return False
            
        try:
            # Create the packet interceptor thread
            self.running = True
            self.interceptor_thread = threading.Thread(target=self._process_queue)
            self.interceptor_thread.daemon = True
            self.interceptor_thread.start()
            
            self.logger.log_system_event("Packet interceptor started")
            return True
        except Exception as e:
            self.logger.log_system_event(f"Error starting packet interceptor: {str(e)}", level="ERROR")
            self.running = False
            return False
    
    def stop(self):
        """Stop intercepting packets"""
        if not self.running:
            return False
            
        try:
            self.running = False
            if self.nfqueue:
                self.nfqueue.unbind()
                
            # Wait for thread to terminate
            if self.interceptor_thread:
                self.interceptor_thread.join(timeout=2.0)
                
            self.logger.log_system_event("Packet interceptor stopped")
            return True
        except Exception as e:
            self.logger.log_system_event(f"Error stopping packet interceptor: {str(e)}", level="ERROR")
            return False
    
    def _process_queue(self):
        """Process packets from the netfilter queue"""
        try:
            self.nfqueue = netfilterqueue.NetfilterQueue()
            self.nfqueue.bind(self.queue_num, self._process_packet)
            self.logger.log_system_event(f"NetfilterQueue bound to queue {self.queue_num}")
            self.nfqueue.run()
        except Exception as e:
            self.logger.log_system_event(f"Error in packet queue: {str(e)}", level="ERROR")
    
    def _process_packet(self, nfpacket):
        """Process a packet from the queue"""
        try:
            # Convert to scapy packet for easier handling
            packet = IP(nfpacket.get_payload())
            
            # Extract packet info
            packet_info = self._extract_packet_info(packet)
            
            # Process through rule engine
            action = self.rule_engine.process_packet(packet_info)
            
            # Either accept or drop the packet
            if action == "ALLOW":
                self.logger.log_allowed_connection(packet_info)
                nfpacket.accept()
            else:  # BLOCK or any other action defaults to block
                self.logger.log_blocked_connection(packet_info)
                # Call the block callback if registered
                if hasattr(self.logger, 'block_callback') and self.logger.block_callback:
                    self.logger.block_callback(packet_info)
                nfpacket.drop()
                
        except Exception as e:
            # If error, accept the packet to avoid breaking connectivity
            self.logger.log_system_event(f"Error processing packet: {str(e)}", level="ERROR")
            nfpacket.accept()
    
    def _extract_packet_info(self, packet):
        """Extract relevant information from a packet"""
        info = {
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "protocol": packet[IP].proto,
            "time": time.time()
        }

        # Add protocol specific information
        if TCP in packet:
            info["src_port"] = packet[TCP].sport
            info["dst_port"] = packet[TCP].dport
            info["protocol_name"] = "TCP"
            info["flags"] = packet[TCP].flags
        elif UDP in packet:
            info["src_port"] = packet[UDP].sport
            info["dst_port"] = packet[UDP].dport
            info["protocol_name"] = "UDP"
        elif ICMP in packet:
            info["protocol_name"] = "ICMP"
            info["icmp_type"] = packet[ICMP].type
            info["icmp_code"] = packet[ICMP].code

        return info