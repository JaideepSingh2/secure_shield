import json
import os
import uuid
from typing import List, Dict, Any, Optional

class RuleManager:
    def __init__(self, rules_file_path, logger):
        self.rules_file_path = rules_file_path
        self.logger = logger
        self.rules = []
        
        # Create rules file if it doesn't exist
        if not os.path.exists(rules_file_path):
            self._create_default_rules()
        else:
            self.load_rules()
    
    def _create_default_rules(self):
        """Create a default rules file"""
        default_rules = [
            {
                "id": str(uuid.uuid4()),
                "name": "Block SSH from outside",
                "src_ip": "0.0.0.0/0",
                "dst_port": "22",
                "protocol": "TCP",
                "action": "BLOCK",
                "profile": "default",
                "priority": 100,
                "enabled": True,
                "description": "Block SSH connections from outside"
            },
            {
                "id": str(uuid.uuid4()),
                "name": "Allow HTTP/HTTPS",
                "dst_port": "80-443",
                "protocol": "TCP",
                "action": "ALLOW",
                "profile": "default",
                "priority": 90,
                "enabled": True,
                "description": "Allow web traffic"
            }
        ]
        self.rules = default_rules
        self.save_rules()
        self.logger.log_system_event("Created default rules file")
    
    def load_rules(self) -> List[Dict[str, Any]]:
        """Load rules from the rules file"""
        try:
            with open(self.rules_file_path, 'r') as f:
                self.rules = json.load(f)
                # Filter out disabled rules
                active_rules = [rule for rule in self.rules if rule.get('enabled', True)]
                self.logger.log_system_event(f"Loaded {len(active_rules)} active rules out of {len(self.rules)} total rules")
                return active_rules
        except Exception as e:
            self.logger.log_system_event(f"Error loading rules: {str(e)}", level="ERROR")
            # Return empty rules if there was an error
            return []
    
    def save_rules(self) -> bool:
        """Save rules to the rules file"""
        try:
            with open(self.rules_file_path, 'w') as f:
                json.dump(self.rules, f, indent=4)
            self.logger.log_system_event(f"Saved {len(self.rules)} rules to file")
            return True
        except Exception as e:
            self.logger.log_system_event(f"Error saving rules: {str(e)}", level="ERROR")
            return False
    
    def add_rule(self, rule: Dict[str, Any]) -> str:
        """Add a new rule and return its ID"""
        # Generate a unique ID for the rule
        rule_id = str(uuid.uuid4())
        rule['id'] = rule_id
        
        # Add default values if not provided
        if 'priority' not in rule:
            rule['priority'] = 50  # Default priority in the middle
        if 'enabled' not in rule:
            rule['enabled'] = True
        if 'profile' not in rule:
            rule['profile'] = 'default'
        
        self.rules.append(rule)
        self.save_rules()
        self.logger.log_system_event(f"Added new rule: {rule.get('name', rule_id)}")
        return rule_id
    
    def update_rule(self, rule_id: str, updated_rule: Dict[str, Any]) -> bool:
        """Update an existing rule by ID"""
        for i, rule in enumerate(self.rules):
            if rule.get('id') == rule_id:
                # Preserve the ID
                updated_rule['id'] = rule_id
                self.rules[i] = updated_rule
                self.save_rules()
                self.logger.log_system_event(f"Updated rule: {updated_rule.get('name', rule_id)}")
                return True
        
        self.logger.log_system_event(f"Rule not found for update: {rule_id}", level="WARNING")
        return False
    
    def delete_rule(self, rule_id: str) -> bool:
        """Delete a rule by ID"""
        for i, rule in enumerate(self.rules):
            if rule.get('id') == rule_id:
                deleted_rule = self.rules.pop(i)
                self.save_rules()
                self.logger.log_system_event(f"Deleted rule: {deleted_rule.get('name', rule_id)}")
                return True
        
        self.logger.log_system_event(f"Rule not found for deletion: {rule_id}", level="WARNING")
        return False
    
    def get_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Get a rule by ID"""
        for rule in self.rules:
            if rule.get('id') == rule_id:
                return rule
        return None
    
    def get_all_profiles(self) -> List[str]:
        """Get a list of all unique profiles"""
        profiles = set()
        for rule in self.rules:
            if 'profile' in rule:
                profiles.add(rule['profile'])
        
        # Always include 'default' profile
        profiles.add('default')
        return sorted(list(profiles))