import ipaddress
from typing import List, Optional, Tuple, Set
from agent.detection.models import DetectionSignal

class SuppressionPolicy:
    def __init__(self):
        # Allowlist configurations
        self.allowed_sources: List[str] = [] # IPs or CIDRs
        self.allowed_destinations: List[str] = []
        self.allowed_rules: Set[str] = set()
        self.allowed_ports: Set[int] = set()
        self.allowed_ip_pairs: List[Tuple[str, str]] = [] # (src_cidr, dst_cidr)
        
    def add_allowed_source(self, cidr: str):
        if cidr == "0.0.0.0/0" or cidr == "::/0":
            return
        self.allowed_sources.append(cidr)
        
    def add_allowed_destination(self, cidr: str):
        if cidr == "0.0.0.0/0" or cidr == "::/0":
            return
        self.allowed_destinations.append(cidr)

    def is_suppressed(self, signal: DetectionSignal) -> Optional[str]:
        if signal.rule_id in self.allowed_rules:
            return f"Rule {signal.rule_id} is globally allowed"
            
        src_ip = None
        if signal.primary_entity:
            try:
                src_ip = ipaddress.ip_address(signal.primary_entity)
            except ValueError:
                pass
                
        if src_ip:
            for allowed in self.allowed_sources:
                try:
                    if src_ip in ipaddress.ip_network(allowed, strict=False):
                        return f"Source {signal.primary_entity} is in allowed sources"
                except ValueError:
                    continue
                    
        if signal.target_entities:
            for target in signal.target_entities:
                try:
                    dst_ip = ipaddress.ip_address(target)
                except ValueError:
                    continue
                    
                for allowed in self.allowed_destinations:
                    try:
                        if dst_ip in ipaddress.ip_network(allowed, strict=False):
                            return f"Destination {target} is in allowed destinations"
                    except ValueError:
                        continue
                        
                if src_ip:
                    for src_cidr, dst_cidr in self.allowed_ip_pairs:
                        try:
                            if src_ip in ipaddress.ip_network(src_cidr, strict=False) and dst_ip in ipaddress.ip_network(dst_cidr, strict=False):
                                return f"IP pair {signal.primary_entity} -> {target} is allowed"
                        except ValueError:
                            continue

        return None
