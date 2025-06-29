from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QPushButton, 
                           QDialog, QFormLayout, QLineEdit, QComboBox, QTableWidgetItem,
                           QHeaderView, QCheckBox, QLabel, QMessageBox, QSpinBox)
from PyQt5.QtCore import Qt, pyqtSignal

class RuleDialog(QDialog):
    """Dialog for creating or editing a firewall rule"""
    def __init__(self, parent=None, rule=None):
        super().__init__(parent)
        self.rule = rule or {}
        self.setWindowTitle("Edit Rule" if rule else "Add Rule")
        self.resize(400, 500)
        self._init_ui()
        
    def _init_ui(self):
        layout = QFormLayout()
        
        # Rule name
        self.name_edit = QLineEdit(self.rule.get('name', ''))
        layout.addRow("Rule Name:", self.name_edit)
        
        # Source IP
        self.src_ip_edit = QLineEdit(self.rule.get('src_ip', ''))
        self.src_ip_edit.setPlaceholderText("e.g. 192.168.1.10 or 192.168.1.0/24")
        layout.addRow("Source IP:", self.src_ip_edit)
        
        # Destination IP
        self.dst_ip_edit = QLineEdit(self.rule.get('dst_ip', ''))
        self.dst_ip_edit.setPlaceholderText("e.g. 8.8.8.8 or 10.0.0.0/8")
        layout.addRow("Destination IP:", self.dst_ip_edit)
        
        # Protocol
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(['ANY', 'TCP', 'UDP', 'ICMP'])
        if 'protocol' in self.rule:
            index = self.protocol_combo.findText(self.rule['protocol'])
            if index >= 0:
                self.protocol_combo.setCurrentIndex(index)
        layout.addRow("Protocol:", self.protocol_combo)
        
        # Source Port
        self.src_port_edit = QLineEdit(str(self.rule.get('src_port', '')))
        self.src_port_edit.setPlaceholderText("e.g. 1024 or 1024-2048")
        layout.addRow("Source Port:", self.src_port_edit)
        
        # Destination Port
        self.dst_port_edit = QLineEdit(str(self.rule.get('dst_port', '')))
        self.dst_port_edit.setPlaceholderText("e.g. 80 or 80,443")
        layout.addRow("Destination Port:", self.dst_port_edit)
        
        # Action
        self.action_combo = QComboBox()
        self.action_combo.addItems(['ALLOW', 'BLOCK'])
        if 'action' in self.rule:
            index = self.action_combo.findText(self.rule['action'])
            if index >= 0:
                self.action_combo.setCurrentIndex(index)
        layout.addRow("Action:", self.action_combo)
        
        # Profile
        self.profile_edit = QLineEdit(self.rule.get('profile', 'default'))
        layout.addRow("Profile:", self.profile_edit)
        
        # Priority
        self.priority_spin = QSpinBox()
        self.priority_spin.setRange(1, 100)
        self.priority_spin.setValue(self.rule.get('priority', 50))
        layout.addRow("Priority:", self.priority_spin)
        
        # Enabled
        self.enabled_checkbox = QCheckBox()
        self.enabled_checkbox.setChecked(self.rule.get('enabled', True))
        layout.addRow("Enabled:", self.enabled_checkbox)
        
        # Description
        self.description_edit = QLineEdit(self.rule.get('description', ''))
        layout.addRow("Description:", self.description_edit)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        save_button = QPushButton("Save")
        save_button.clicked.connect(self.accept)
        button_layout.addWidget(save_button)
        
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)
        
        layout.addRow("", button_layout)
        
        self.setLayout(layout)
        
    def get_rule(self):
        """Get the rule data from the form"""
        rule = {
            'name': self.name_edit.text(),
            'protocol': self.protocol_combo.currentText(),
            'action': self.action_combo.currentText(),
            'profile': self.profile_edit.text(),
            'priority': self.priority_spin.value(),
            'enabled': self.enabled_checkbox.isChecked(),
            'description': self.description_edit.text()
        }
        
        # Add optional fields only if they contain data
        if self.src_ip_edit.text():
            rule['src_ip'] = self.src_ip_edit.text()
        
        if self.dst_ip_edit.text():
            rule['dst_ip'] = self.dst_ip_edit.text()
        
        if self.src_port_edit.text():
            rule['src_port'] = self.src_port_edit.text()
        
        if self.dst_port_edit.text():
            rule['dst_port'] = self.dst_port_edit.text()
            
        # Preserve the original ID if we're editing
        if 'id' in self.rule:
            rule['id'] = self.rule['id']
            
        return rule

class RulesEditorWidget(QWidget):
    """Widget for editing firewall rules"""
    rule_changed = pyqtSignal()
    
    def __init__(self, rule_manager=None, parent=None):
        super().__init__(parent)
        self.rule_manager = rule_manager
        self._init_ui()
        
        # Load rules if rule manager is provided
        if rule_manager:
            self.load_rules()
        
    def _init_ui(self):
        layout = QVBoxLayout()
        
        # Table for displaying rules
        self.rules_table = QTableWidget(0, 8)  # Rows will be added later
        self.rules_table.setHorizontalHeaderLabels([
            "Name", "Source IP", "Destination IP", "Protocol", 
            "Ports", "Action", "Profile", "Enabled"
        ])
        
        # Set column stretch
        header = self.rules_table.horizontalHeader()
        for i in range(8):
            header.setSectionResizeMode(i, QHeaderView.Stretch)
        
        layout.addWidget(self.rules_table)
        
        # Buttons layout
        button_layout = QHBoxLayout()
        
        # Add rule button
        self.add_button = QPushButton("Add Rule")
        self.add_button.clicked.connect(self._add_rule)
        button_layout.addWidget(self.add_button)
        
        # Edit rule button
        self.edit_button = QPushButton("Edit Rule")
        self.edit_button.clicked.connect(self._edit_rule)
        button_layout.addWidget(self.edit_button)
        
        # Delete rule button
        self.delete_button = QPushButton("Delete Rule")
        self.delete_button.clicked.connect(self._delete_rule)
        button_layout.addWidget(self.delete_button)
        
        # Rule profiles selector
        self.profile_label = QLabel("Profile:")
        button_layout.addWidget(self.profile_label)
        
        self.profile_combo = QComboBox()
        self.profile_combo.addItem("All Profiles")
        self.profile_combo.addItem("default")
        self.profile_combo.currentTextChanged.connect(self._filter_rules)
        button_layout.addWidget(self.profile_combo)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def load_rules(self):
        """Load rules from the rule manager"""
        if not self.rule_manager:
            return
        
        # Get all rules
        rules = self.rule_manager.rules
        
        # Update the table
        self._populate_table(rules)
        
        # Update profiles in combo box
        self._update_profiles()
    
    def _update_profiles(self):
        """Update the list of available profiles"""
        if not self.rule_manager:
            return
            
        # Get all unique profiles - extract directly from rules to avoid recursion
        profiles = set()
        for rule in self.rule_manager.rules:
            if 'profile' in rule:
                profiles.add(rule['profile'])
        
        # Always include 'default' profile
        profiles.add('default')
        profiles = sorted(list(profiles))
        
        # Save current selection
        current = self.profile_combo.currentText()
        
        # Update combo box
        self.profile_combo.clear()
        self.profile_combo.addItem("All Profiles")
        self.profile_combo.addItems(profiles)
        
        # Restore selection if possible
        index = self.profile_combo.findText(current)
        if index >= 0:
            self.profile_combo.setCurrentIndex(index)
    
    def _populate_table(self, rules):
        """Populate the table with rules"""
        self.rules_table.setRowCount(0)  # Clear existing rows
        
        # Filter by selected profile if needed
        selected_profile = self.profile_combo.currentText()
        if selected_profile != "All Profiles":
            rules = [rule for rule in rules if rule.get('profile') == selected_profile]
        
        # Add rules to table
        for row, rule in enumerate(rules):
            self.rules_table.insertRow(row)
            
            # Add rule data to table cells
            self.rules_table.setItem(row, 0, QTableWidgetItem(rule.get('name', 'Unnamed')))
            self.rules_table.setItem(row, 1, QTableWidgetItem(rule.get('src_ip', '*')))
            self.rules_table.setItem(row, 2, QTableWidgetItem(rule.get('dst_ip', '*')))
            self.rules_table.setItem(row, 3, QTableWidgetItem(rule.get('protocol', 'ANY')))
            
            # Combine ports for display
            ports = ""
            if 'src_port' in rule:
                ports += f"Src: {rule['src_port']}"
            if 'dst_port' in rule:
                if ports:
                    ports += ", "
                ports += f"Dst: {rule['dst_port']}"
            self.rules_table.setItem(row, 4, QTableWidgetItem(ports or '*'))
            
            # Action and profile
            self.rules_table.setItem(row, 5, QTableWidgetItem(rule.get('action', 'ALLOW')))
            self.rules_table.setItem(row, 6, QTableWidgetItem(rule.get('profile', 'default')))
            
            # Enabled status
            enabled_item = QTableWidgetItem()
            enabled_item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            enabled_item.setCheckState(Qt.Checked if rule.get('enabled', True) else Qt.Unchecked)
            self.rules_table.setItem(row, 7, enabled_item)
            
            # Store the rule ID as item data
            if 'id' in rule:
                self.rules_table.item(row, 0).setData(Qt.UserRole, rule['id'])
    
    def _filter_rules(self):
        """Filter rules based on selected profile"""
        # Fixed version that doesn't cause recursion
        if not self.rule_manager:
            return
            
        # Get all rules
        rules = self.rule_manager.rules
        
        # Filter by selected profile
        selected_profile = self.profile_combo.currentText()
        if selected_profile != "All Profiles":
            filtered_rules = [rule for rule in rules if rule.get('profile') == selected_profile]
        else:
            filtered_rules = rules
            
        # Update the table directly without calling load_rules()
        self._populate_table(filtered_rules)
    
    def _get_selected_rule_id(self):
        """Get the ID of the selected rule"""
        selected_rows = self.rules_table.selectedItems()
        if not selected_rows:
            return None
            
        # Get the ID from the first column of selected row
        row = selected_rows[0].row()
        return self.rules_table.item(row, 0).data(Qt.UserRole)
    
    def _add_rule(self):
        """Open dialog to add a new rule"""
        if not self.rule_manager:
            QMessageBox.warning(self, "Error", "Rule manager not initialized")
            return
            
        dialog = RuleDialog(self)
        if dialog.exec_():
            # Get the new rule data
            rule = dialog.get_rule()
            
            # Add the rule using rule manager
            rule_id = self.rule_manager.add_rule(rule)
            
            # Reload the table
            self.load_rules()
            
            # Emit signal
            self.rule_changed.emit()
    
    def _edit_rule(self):
        """Open dialog to edit the selected rule"""
        if not self.rule_manager:
            QMessageBox.warning(self, "Error", "Rule manager not initialized")
            return
            
        rule_id = self._get_selected_rule_id()
        if not rule_id:
            QMessageBox.information(self, "Select Rule", "Please select a rule to edit")
            return
            
        # Get the full rule data
        rule = self.rule_manager.get_rule(rule_id)
        if not rule:
            QMessageBox.warning(self, "Error", "Rule not found")
            return
            
        # Open edit dialog
        dialog = RuleDialog(self, rule)
        if dialog.exec_():
            # Get the updated rule data
            updated_rule = dialog.get_rule()
            
            # Update the rule
            self.rule_manager.update_rule(rule_id, updated_rule)
            
            # Reload the table
            self.load_rules()
            
            # Emit signal
            self.rule_changed.emit()
    
    def _delete_rule(self):
        """Delete the selected rule"""
        if not self.rule_manager:
            QMessageBox.warning(self, "Error", "Rule manager not initialized")
            return
            
        rule_id = self._get_selected_rule_id()
        if not rule_id:
            QMessageBox.information(self, "Select Rule", "Please select a rule to edit")
            return
            
        # Confirm deletion
        reply = QMessageBox.question(self, "Confirm Deletion", 
                                    "Are you sure you want to delete this rule?",
                                    QMessageBox.Yes | QMessageBox.No)
                                    
        if reply == QMessageBox.Yes:
            # Delete the rule
            self.rule_manager.delete_rule(rule_id)
            
            # Reload the table
            self.load_rules()
            
            # Emit signal
            self.rule_changed.emit()