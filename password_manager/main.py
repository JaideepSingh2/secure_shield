import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import pyperclip
import os
import sys
from functools import partial

# Import your existing classes
from src.auth import MasterPasswordAuth
from src.encryption import PasswordEncryption
from src.password_store import PasswordStore
from src.password_generator import PasswordGenerator
from src.password_strength import PasswordStrengthChecker

class PasswordEntryDialog(tk.Toplevel):
    """Custom dialog for password input with asterisk masking"""
    def __init__(self, parent, title, prompt):
        super().__init__(parent)
        self.title(title)
        self.result = None
        self.geometry("300x150")
        self.resizable(False, False)
        
        # Make modal
        self.transient(parent)
        self.grab_set()
        
        # Create widgets
        ttk.Label(self, text=prompt).pack(pady=(10, 5))
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(self, textvariable=self.password_var, show="*")
        self.password_entry.pack(fill=tk.X, padx=20, pady=5)
        self.password_entry.focus_set()
        
        button_frame = ttk.Frame(self)
        button_frame.pack(fill=tk.X, padx=20, pady=(10, 20))
        
        ttk.Button(button_frame, text="OK", command=self.ok_clicked).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.cancel_clicked).pack(side=tk.RIGHT, padx=5)
        
        # Handle window close
        self.protocol("WM_DELETE_WINDOW", self.cancel_clicked)
        
        # Wait for window to be destroyed
        self.wait_window(self)
    
    def ok_clicked(self):
        self.result = self.password_var.get()
        self.destroy()
    
    def cancel_clicked(self):
        self.result = None
        self.destroy()

class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("800x600")
        self.root.minsize(600, 400)
        
        # Set up core components
        self.auth = MasterPasswordAuth()
        self.encryption = None
        self.password_store = None
        self.password_generator = PasswordGenerator()
        self.strength_checker = PasswordStrengthChecker()
        self.authenticated = False
        self.current_frame = None
        
        # Set up main container frame
        self.main_frame = ttk.Frame(self.root, padding=10)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Start with authentication
        self.show_auth_screen()
    
    def show_auth_screen(self):
        """Show the login or setup screen"""
        if self.current_frame:
            self.current_frame.destroy()
        
        auth_frame = ttk.Frame(self.main_frame, padding=20)
        auth_frame.pack(fill=tk.BOTH, expand=True)
        self.current_frame = auth_frame
        
        # Center the login content
        content_frame = ttk.Frame(auth_frame)
        content_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        
        ttk.Label(content_frame, text="Password Manager", font=("Arial", 18, "bold")).pack(pady=(0, 20))
        
        if self.auth.is_configured():
            ttk.Label(content_frame, text="Enter your master password to continue").pack(pady=(0, 10))
            
            password_var = tk.StringVar()
            password_entry = ttk.Entry(content_frame, textvariable=password_var, show="*", width=30)
            password_entry.pack(pady=5)
            password_entry.focus_set()
            
            error_label = ttk.Label(content_frame, text="", foreground="red")
            error_label.pack(pady=5)
            
            ttk.Button(content_frame, text="Login", 
                       command=lambda: self.login(password_var.get(), error_label)).pack(pady=10)
                       
            # Bind Enter key to login
            password_entry.bind("<Return>", lambda event: self.login(password_var.get(), error_label))
        else:
            ttk.Label(content_frame, text="No master password found. Let's set one up.").pack(pady=10)
            
            password_var = tk.StringVar()
            confirm_var = tk.StringVar()
            
            ttk.Label(content_frame, text="Enter a master password:").pack(anchor=tk.W, pady=(10, 0))
            password_entry = ttk.Entry(content_frame, textvariable=password_var, show="*", width=30)
            password_entry.pack(pady=5)
            password_entry.focus_set()
            
            # Add strength indicator
            strength_frame = ttk.Frame(content_frame)
            strength_frame.pack(fill=tk.X, pady=5)
            
            strength_var = tk.StringVar(value="Password strength: Not calculated")
            ttk.Label(strength_frame, textvariable=strength_var).pack(anchor=tk.W)
            
            strength_bar = ttk.Progressbar(strength_frame, length=200, mode="determinate")
            strength_bar.pack(anchor=tk.W, pady=2)
            
            feedback_var = tk.StringVar()
            feedback_label = ttk.Label(content_frame, textvariable=feedback_var, wraplength=300, foreground="#555555")
            feedback_label.pack(pady=2)
            
            # Check strength when password changes
            def check_master_password_strength(*args):
                password = password_var.get()
                if password:
                    score, category, feedback = self.strength_checker.check_strength(password)
                    strength_var.set(f"Password strength: {category} ({score}/100)")
                    strength_bar["value"] = score
                    feedback_var.set(feedback)
                else:
                    strength_var.set("Password strength: Not calculated")
                    strength_bar["value"] = 0
                    feedback_var.set("")
            
            password_var.trace_add("write", check_master_password_strength)
            
            ttk.Label(content_frame, text="Confirm master password:").pack(anchor=tk.W, pady=(10, 0))
            ttk.Entry(content_frame, textvariable=confirm_var, show="*", width=30).pack(pady=5)
            
            error_label = ttk.Label(content_frame, text="", foreground="red")
            error_label.pack(pady=5)
            
            ttk.Button(content_frame, text="Create", 
                       command=lambda: self.setup(password_var.get(), confirm_var.get(), error_label, strength_bar["value"])).pack(pady=10)
    
    def login(self, password, error_label):
        """Handle login attempts"""
        if not password:
            error_label.config(text="Password cannot be empty")
            return
        
        if self.auth.authenticate(password):
            # Initialize encryption with the derived key
            self.encryption = PasswordEncryption(self.auth.get_encryption_key())
            
            # Initialize password store
            self.password_store = PasswordStore(encryption=self.encryption)
            
            self.authenticated = True
            self.show_main_screen()
        else:
            error_label.config(text="Incorrect password. Please try again.")
    
    def setup(self, password, confirm, error_label, strength_score=0):
        """Handle first-time setup"""
        if not password:
            error_label.config(text="Password cannot be empty")
            return
        
        if password != confirm:
            error_label.config(text="Passwords don't match")
            return
        
        # Check password strength
        if strength_score < 40:  # Using 40 as minimum threshold for acceptable passwords
            error_label.config(text="Password is too weak. Please choose a stronger password.")
            return
        
        self.auth.setup_master_password(password)
        
        # Initialize encryption with the derived key
        self.encryption = PasswordEncryption(self.auth.get_encryption_key())
        
        # Initialize password store
        self.password_store = PasswordStore(encryption=self.encryption)
        
        self.authenticated = True
        messagebox.showinfo("Setup Complete", "Master password set up successfully!")
        self.show_main_screen()
    
    def show_main_screen(self):
        """Show the main password manager interface"""
        if self.current_frame:
            self.current_frame.destroy()
        
        # Create main app frame with sidebar and content area
        main_app_frame = ttk.Frame(self.main_frame)
        main_app_frame.pack(fill=tk.BOTH, expand=True)
        self.current_frame = main_app_frame
        
        # Create sidebar
        sidebar_frame = ttk.Frame(main_app_frame, width=200, relief=tk.RIDGE, borderwidth=1)
        sidebar_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10), pady=5)
        sidebar_frame.pack_propagate(False)  # Prevent sidebar from shrinking
        
        # Create content area
        self.content_frame = ttk.Frame(main_app_frame)
        self.content_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, pady=5)
        
        # Add buttons to sidebar
        sidebar_title = ttk.Label(sidebar_frame, text="Menu", font=("Arial", 12, "bold"))
        sidebar_title.pack(pady=10)
        
        button_style = {"width": 20, "padding": 5}
        
        ttk.Button(sidebar_frame, text="View Passwords", 
                   command=self.show_password_list, **button_style).pack(fill=tk.X, padx=5, pady=2)
        ttk.Button(sidebar_frame, text="Add Password", 
                   command=self.show_add_password, **button_style).pack(fill=tk.X, padx=5, pady=2)
        ttk.Button(sidebar_frame, text="Generate Password", 
                   command=self.show_generate_password, **button_style).pack(fill=tk.X, padx=5, pady=2)
        ttk.Button(sidebar_frame, text="Check Password Strength", 
                   command=self.show_check_strength, **button_style).pack(fill=tk.X, padx=5, pady=2)
        ttk.Button(sidebar_frame, text="Logout", 
                   command=self.logout, **button_style).pack(fill=tk.X, padx=5, pady=2)
        
        # Show password list by default
        self.show_password_list()
    
    def show_password_list(self):
        """Show the list of saved passwords"""
        self.clear_content_frame()
        
        # Add title
        ttk.Label(self.content_frame, text="Stored Passwords", font=("Arial", 14, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        # Get all sites
        sites = self.password_store.get_all_sites()
        
        if not sites:
            ttk.Label(self.content_frame, text="No passwords stored yet").pack(anchor=tk.W)
            return
        
        # Create treeview for passwords
        columns = ("site", "username")
        tree = ttk.Treeview(self.content_frame, columns=columns, show="headings", selectmode="browse")
        tree.heading("site", text="Site/Application")
        tree.heading("username", text="Username")
        tree.column("site", width=200)
        tree.column("username", width=200)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.content_frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack the tree and scrollbar
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Add data to tree
        for site in sites:
            entry = self.password_store.get_password(site)
            if entry:
                tree.insert("", tk.END, values=(site, entry["username"]))
        
        # Action buttons frame
        action_frame = ttk.Frame(self.content_frame)
        action_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(action_frame, text="View Details", 
                   command=lambda: self.view_password_details(tree)).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Edit", 
                   command=lambda: self.edit_password(tree)).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Delete", 
                   command=lambda: self.delete_password(tree)).pack(side=tk.LEFT, padx=5)
        
        # Double-click to view details
        tree.bind("<Double-1>", lambda event: self.view_password_details(tree))
    
    def view_password_details(self, tree):
        """View details of a selected password"""
        selection = tree.selection()
        if not selection:
            messagebox.showinfo("No Selection", "Please select a password entry to view.")
            return
        
        # Get site name from the selected item
        site = tree.item(selection, "values")[0]
        entry = self.password_store.get_password(site)
        
        if not entry:
            messagebox.showerror("Error", f"Could not retrieve details for {site}")
            return
        
        # Create details dialog
        details_dialog = tk.Toplevel(self.root)
        details_dialog.title(f"Password Details - {site}")
        details_dialog.geometry("400x300")
        details_dialog.transient(self.root)
        details_dialog.grab_set()
        
        details_frame = ttk.Frame(details_dialog, padding=20)
        details_frame.pack(fill=tk.BOTH, expand=True)
        
        # Site
        ttk.Label(details_frame, text="Site/Application:", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Label(details_frame, text=site).grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # Username
        ttk.Label(details_frame, text="Username:", font=("Arial", 10, "bold")).grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Label(details_frame, text=entry["username"]).grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # Password (masked)
        ttk.Label(details_frame, text="Password:", font=("Arial", 10, "bold")).grid(row=2, column=0, sticky=tk.W, pady=5)
        
        password_frame = ttk.Frame(details_frame)
        password_frame.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        password_var = tk.StringVar(value="•" * 8)
        show_password = tk.BooleanVar(value=False)
        
        password_label = ttk.Label(password_frame, textvariable=password_var)
        password_label.pack(side=tk.LEFT)
        
        def toggle_password():
            if show_password.get():
                password_var.set(entry["password"])
            else:
                password_var.set("•" * 8)
        
        ttk.Checkbutton(password_frame, text="Show", variable=show_password, 
                        command=toggle_password).pack(side=tk.LEFT, padx=10)
        
        # Copy button
        ttk.Button(password_frame, text="Copy", 
                   command=lambda: self.copy_to_clipboard(entry["password"], "Password")).pack(side=tk.LEFT)
        
        # Notes
        ttk.Label(details_frame, text="Notes:", font=("Arial", 10, "bold")).grid(row=3, column=0, sticky=tk.NW, pady=5)
        
        notes_text = tk.Text(details_frame, height=5, width=30, wrap=tk.WORD)
        notes_text.grid(row=3, column=1, sticky=tk.W, pady=5)
        notes_text.insert(tk.END, entry.get("notes", ""))
        notes_text.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(details_frame, text="Close", command=details_dialog.destroy).grid(row=4, column=1, sticky=tk.E, pady=10)
    
    def edit_password(self, tree):
        """Edit a selected password"""
        selection = tree.selection()
        if not selection:
            messagebox.showinfo("No Selection", "Please select a password entry to edit.")
            return
        
        # Get site name from the selected item
        site = tree.item(selection, "values")[0]
        entry = self.password_store.get_password(site)
        
        if not entry:
            messagebox.showerror("Error", f"Could not retrieve details for {site}")
            return
        
        # Show add password dialog with existing values
        self.show_add_password(edit_site=site, edit_entry=entry)
    
    def delete_password(self, tree):
        """Delete a selected password"""
        selection = tree.selection()
        if not selection:
            messagebox.showinfo("No Selection", "Please select a password entry to delete.")
            return
        
        # Get site name from the selected item
        site = tree.item(selection, "values")[0]
        
        # Confirm deletion
        confirm = messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete the entry for {site}?")
        if confirm:
            if self.password_store.delete_password(site):
                messagebox.showinfo("Success", f"Entry for {site} deleted successfully!")
                self.show_password_list()  # Refresh the list
            else:
                messagebox.showerror("Error", f"Could not delete entry for {site}")
    
    def show_add_password(self, edit_site=None, edit_entry=None):
        """Show the add password form"""
        self.clear_content_frame()
        
        # Set title based on mode (add or edit)
        title = "Edit Password" if edit_site else "Add New Password"
        ttk.Label(self.content_frame, text=title, font=("Arial", 14, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        # Create form frame
        form_frame = ttk.Frame(self.content_frame)
        form_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Site
        ttk.Label(form_frame, text="Site/Application:").grid(row=0, column=0, sticky=tk.W, pady=5)
        site_var = tk.StringVar(value=edit_site if edit_site else "")
        site_entry = ttk.Entry(form_frame, textvariable=site_var, width=30)
        site_entry.grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # If editing, disable site field
        if edit_site:
            site_entry.config(state="disabled")
        
        # Username
        ttk.Label(form_frame, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=5)
        username_var = tk.StringVar(value=edit_entry["username"] if edit_entry else "")
        ttk.Entry(form_frame, textvariable=username_var, width=30).grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # Password
        ttk.Label(form_frame, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        
        password_frame = ttk.Frame(form_frame)
        password_frame.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        password_var = tk.StringVar(value=edit_entry["password"] if edit_entry else "")
        password_entry = ttk.Entry(password_frame, textvariable=password_var, show="*", width=30)
        password_entry.pack(side=tk.LEFT)
        
        # Toggle password visibility
        show_password = tk.BooleanVar(value=False)
        
        def toggle_password():
            password_entry.config(show="" if show_password.get() else "*")
        
        ttk.Checkbutton(password_frame, text="Show", variable=show_password, 
                        command=toggle_password).pack(side=tk.LEFT, padx=5)
        
        # Generate password button
        ttk.Button(password_frame, text="Generate", 
                   command=lambda: self.generate_for_field(password_var)).pack(side=tk.LEFT, padx=5)
        
        # Notes
        ttk.Label(form_frame, text="Notes:").grid(row=3, column=0, sticky=tk.NW, pady=5)
        notes_text = tk.Text(form_frame, height=5, width=30, wrap=tk.WORD)
        notes_text.grid(row=3, column=1, sticky=tk.W, pady=5)
        
        # If editing, populate notes
        if edit_entry and "notes" in edit_entry:
            notes_text.insert(tk.END, edit_entry["notes"])
        
        # Password strength indicator
        strength_frame = ttk.Frame(form_frame)
        strength_frame.grid(row=4, column=1, sticky=tk.W, pady=5)
        
        strength_var = tk.StringVar(value="Password strength: Not calculated")
        ttk.Label(strength_frame, textvariable=strength_var).pack(side=tk.LEFT)
        
        strength_bar = ttk.Progressbar(strength_frame, length=200, mode="determinate")
        strength_bar.pack(side=tk.LEFT, padx=10)
        
        feedback_var = tk.StringVar()
        ttk.Label(form_frame, textvariable=feedback_var, wraplength=400).grid(row=5, column=1, sticky=tk.W, pady=5)
        
        # Update strength when password changes
        def check_password_strength(*args):
            if password_var.get():
                score, category, feedback = self.strength_checker.check_strength(password_var.get())
                strength_var.set(f"Password strength: {category} ({score}/100)")
                strength_bar["value"] = score
                feedback_var.set(feedback)
            else:
                strength_var.set("Password strength: Not calculated")
                strength_bar["value"] = 0
                feedback_var.set("")
        
        password_var.trace_add("write", check_password_strength)
        
        # Check initial password if editing
        if edit_entry:
            check_password_strength()
        
        # Buttons
        button_frame = ttk.Frame(form_frame)
        button_frame.grid(row=6, column=1, sticky=tk.E, pady=10)
        
        save_text = "Update" if edit_site else "Save"
        
        ttk.Button(button_frame, text=save_text, 
                   command=lambda: self.save_password(
                       site_var.get(), 
                       username_var.get(), 
                       password_var.get(), 
                       notes_text.get("1.0", tk.END).strip(),
                       edit_site
                   )).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Cancel", 
                   command=self.show_password_list).pack(side=tk.LEFT, padx=5)
    
    def save_password(self, site, username, password, notes, edit_site=None):
        """Save a new password or update an existing one"""
        if not site:
            messagebox.showerror("Error", "Site/Application name cannot be empty")
            return
        
        if not username:
            messagebox.showerror("Error", "Username cannot be empty")
            return
        
        if not password:
            messagebox.showerror("Error", "Password cannot be empty")
            return
        
        try:
            # If editing, use original site name
            actual_site = edit_site if edit_site else site
            
            self.password_store.add_password(actual_site, username, password, notes)
            
            action = "updated" if edit_site else "saved"
            messagebox.showinfo("Success", f"Password for {actual_site} {action} successfully!")
            
            # Go back to password list
            self.show_password_list()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save password: {str(e)}")
    
    def show_generate_password(self):
        """Show the password generator screen"""
        self.clear_content_frame()
        
        # Add title
        ttk.Label(self.content_frame, text="Password Generator", font=("Arial", 14, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        # Create options frame
        options_frame = ttk.Frame(self.content_frame)
        options_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Length
        ttk.Label(options_frame, text="Password Length:").grid(row=0, column=0, sticky=tk.W, pady=5)
        
        length_var = tk.IntVar(value=16)
        length_frame = ttk.Frame(options_frame)
        length_frame.grid(row=0, column=1, sticky=tk.W, pady=5)
        
        length_scale = ttk.Scale(length_frame, from_=8, to=64, variable=length_var, length=200)
        length_scale.pack(side=tk.LEFT)
        
        length_label = ttk.Label(length_frame, textvariable=length_var, width=3)
        length_label.pack(side=tk.LEFT, padx=10)
        
        # Character options
        ttk.Label(options_frame, text="Character Types:").grid(row=1, column=0, sticky=tk.W, pady=5)
        
        char_options_frame = ttk.Frame(options_frame)
        char_options_frame.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        uppercase_var = tk.BooleanVar(value=True)
        lowercase_var = tk.BooleanVar(value=True)
        digits_var = tk.BooleanVar(value=True)
        special_var = tk.BooleanVar(value=True)
        exclude_similar_var = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(char_options_frame, text="Uppercase Letters (A-Z)", 
                        variable=uppercase_var).pack(anchor=tk.W)
        ttk.Checkbutton(char_options_frame, text="Lowercase Letters (a-z)", 
                        variable=lowercase_var).pack(anchor=tk.W)
        ttk.Checkbutton(char_options_frame, text="Digits (0-9)", 
                        variable=digits_var).pack(anchor=tk.W)
        ttk.Checkbutton(char_options_frame, text="Special Characters (!@#$%)", 
                        variable=special_var).pack(anchor=tk.W)
        ttk.Checkbutton(char_options_frame, text="Exclude Similar Characters (I, l, 1, O, 0)", 
                        variable=exclude_similar_var).pack(anchor=tk.W)
        
        # Generate button
        ttk.Button(options_frame, text="Generate Password", 
                   command=lambda: self.generate_password_action(
                       length_var.get(),
                       uppercase_var.get(),
                       lowercase_var.get(),
                       digits_var.get(),
                       special_var.get(),
                       exclude_similar_var.get()
                   )).grid(row=2, column=1, sticky=tk.W, pady=15)
        
        # Result frame
        result_frame = ttk.LabelFrame(self.content_frame, text="Generated Password", padding=10)
        result_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.password_result_var = tk.StringVar()
        result_entry = ttk.Entry(result_frame, textvariable=self.password_result_var, width=50, font=("Courier", 10))
        result_entry.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Copy button
        ttk.Button(result_frame, text="Copy", 
                   command=lambda: self.copy_to_clipboard(self.password_result_var.get(), "Password")).pack(side=tk.LEFT, padx=5)
        
        # Password strength display
        strength_frame = ttk.Frame(self.content_frame)
        strength_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.strength_var = tk.StringVar()
        ttk.Label(strength_frame, textvariable=self.strength_var).pack(anchor=tk.W)
        
        self.strength_bar = ttk.Progressbar(strength_frame, length=400, mode="determinate")
        self.strength_bar.pack(anchor=tk.W, pady=5)
        
        self.feedback_var = tk.StringVar()
        ttk.Label(strength_frame, textvariable=self.feedback_var, wraplength=500).pack(anchor=tk.W)
    
    def generate_password_action(self, length, use_uppercase, use_lowercase, use_digits, use_special, exclude_similar):
        """Generate a password with the specified options"""
        try:
            # Ensure at least one character type is selected
            if not any([use_uppercase, use_lowercase, use_digits, use_special]):
                messagebox.showerror("Error", "Please select at least one character type")
                return
            
            password = self.password_generator.generate_password(
                length=length,
                use_uppercase=use_uppercase,
                use_lowercase=use_lowercase,
                use_digits=use_digits,
                use_special=use_special,
                exclude_similar=exclude_similar
            )
            
            # Display the password
            self.password_result_var.set(password)
            
            # Check and display strength
            score, category, feedback = self.strength_checker.check_strength(password)
            self.strength_var.set(f"Password strength: {category} ({score}/100)")
            self.strength_bar["value"] = score
            self.feedback_var.set(feedback)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate password: {str(e)}")
    
    def generate_for_field(self, password_var):
        """Generate a password for a specific field"""
        try:
            password = self.password_generator.generate_password()
            password_var.set(password)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate password: {str(e)}")
    
    def show_check_strength(self):
        """Show the password strength checker screen"""
        self.clear_content_frame()
        
        # Add title
        ttk.Label(self.content_frame, text="Password Strength Checker", font=("Arial", 14, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        # Create input frame
        input_frame = ttk.Frame(self.content_frame)
        input_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(input_frame, text="Enter password to check:").pack(anchor=tk.W)
        
        password_var = tk.StringVar()
        password_entry = ttk.Entry(input_frame, textvariable=password_var, show="*", width=30)
        password_entry.pack(anchor=tk.W, pady=5)
        
        # Show/hide password
        show_var = tk.BooleanVar(value=False)
        
        def toggle_visibility():
            password_entry.config(show="" if show_var.get() else "*")
        
        ttk.Checkbutton(input_frame, text="Show password", 
                        variable=show_var, command=toggle_visibility).pack(anchor=tk.W)
        
        # Check button
        ttk.Button(input_frame, text="Check Strength", 
                   command=lambda: self.check_password_strength_action(password_var.get())).pack(anchor=tk.W, pady=10)
        
        # Results frame
        results_frame = ttk.LabelFrame(self.content_frame, text="Results", padding=10)
        results_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.strength_result_var = tk.StringVar()
        ttk.Label(results_frame, textvariable=self.strength_result_var, font=("Arial", 10, "bold")).pack(anchor=tk.W)
        
        self.strength_result_bar = ttk.Progressbar(results_frame, length=400, mode="determinate")
        self.strength_result_bar.pack(anchor=tk.W, pady=5)
        
        self.feedback_result_var = tk.StringVar()
        ttk.Label(results_frame, textvariable=self.feedback_result_var, wraplength=500).pack(anchor=tk.W)
    
    def check_password_strength_action(self, password):
        """Check the strength of a given password"""
        if not password:
            messagebox.showinfo("No Password", "Please enter a password to check")
            return
        
        score, category, feedback = self.strength_checker.check_strength(password)
        
        self.strength_result_var.set(f"Password strength: {category} ({score}/100)")
        self.strength_result_bar["value"] = score
        self.feedback_result_var.set(feedback)
    
    def copy_to_clipboard(self, text, item_name="Text"):
        """Copy text to clipboard"""
        try:
            pyperclip.copy(text)
            messagebox.showinfo("Copied", f"{item_name} copied to clipboard")
        except Exception as e:
            messagebox.showerror("Error", "Could not copy to clipboard. Make sure you have xclip or xsel installed.")
    
    def clear_content_frame(self):
        """Clear all widgets from the content frame"""
        for widget in self.content_frame.winfo_children():
            widget.destroy()
    
    def logout(self):
        """Logout of the application"""
        self.authenticated = False
        self.encryption = None
        self.password_store = None
        self.show_auth_screen()

def main():
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    
    # Set app icon if available
    # try:
    #     icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.png")
    #     if os.path.exists(icon_path):
    #         icon = tk.PhotoImage(file=icon_path)
    #         root.iconphoto(True, icon)
    # except Exception:
    #     pass
    
    # Configure style
    style = ttk.Style()
    style.configure("TButton", padding=6)
    style.configure("TLabel", font=("Arial", 10))
    style.configure("TEntry", padding=5)
    
    root.mainloop()

if __name__ == "__main__":
    main()