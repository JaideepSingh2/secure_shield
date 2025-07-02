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

# Color scheme matching the antivirus
COLORS = {
    "bg_dark": "#1E1E1E",         # Dark background
    "bg_medium": "#252526",        # Medium background for panels
    "bg_light": "#333333",         # Lighter background for inputs
    "accent": "#007ACC",           # Accent color (blue)
    "accent_hover": "#1F8AD2",     # Accent hover
    "success": "#6A9955",          # Success/safe color
    "warning": "#D7BA7D",          # Warning color
    "error": "#F14C4C",            # Error/threat color
    "text": "#D4D4D4",             # Primary text
    "text_dim": "#A0A0A0",         # Secondary text
    "border": "#454545"            # Border color
}

class PasswordEntryDialog(tk.Toplevel):
    """Custom dialog for password input with asterisk masking"""
    def __init__(self, parent, title, prompt):
        super().__init__(parent)
        self.title(title)
        self.result = None
        self.geometry("350x180")
        self.resizable(False, False)
        self.configure(bg=COLORS["bg_dark"])
        
        # Make modal
        self.transient(parent)
        self.grab_set()
        
        # Create widgets
        prompt_label = tk.Label(self, text=prompt, 
                               bg=COLORS["bg_dark"], fg=COLORS["text"],
                               font=('Segoe UI', 10))
        prompt_label.pack(pady=(15, 10))
        
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(self, textvariable=self.password_var, show="*",
                                     bg=COLORS["bg_light"], fg=COLORS["text"],
                                     insertbackground=COLORS["text"],
                                     font=('Segoe UI', 10), width=25)
        self.password_entry.pack(padx=20, pady=10)
        self.password_entry.focus_set()
        
        button_frame = tk.Frame(self, bg=COLORS["bg_dark"])
        button_frame.pack(fill=tk.X, padx=20, pady=(10, 20))
        
        ok_btn = tk.Button(button_frame, text="OK", command=self.ok_clicked,
                          bg=COLORS["accent"], fg="white",
                          activebackground=COLORS["accent_hover"],
                          activeforeground="white",
                          font=('Segoe UI', 10), padx=20, pady=5, border=0)
        ok_btn.pack(side=tk.RIGHT, padx=5)
        
        cancel_btn = tk.Button(button_frame, text="Cancel", command=self.cancel_clicked,
                              bg=COLORS["bg_light"], fg=COLORS["text"],
                              activebackground=COLORS["bg_medium"],
                              activeforeground=COLORS["text"],
                              font=('Segoe UI', 10), padx=20, pady=5, border=0)
        cancel_btn.pack(side=tk.RIGHT, padx=5)
        
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

class StyleManager:
    """Manages application styling and themes - matching antivirus style"""
    def __init__(self):
        self.style = ttk.Style()
    
    def setup_styles(self):
        """Configure ttk styles for the application"""
        self.style.theme_use('default')
        
        # Configure colors
        self.style.configure('TFrame', background=COLORS["bg_dark"])
        self.style.configure('TSeparator', background=COLORS["bg_dark"])
        
        # Button styles
        self.style.configure('Primary.TButton', 
                            background=COLORS["accent"],
                            foreground='white', 
                            font=('Segoe UI', 10),
                            padding=10)
        
        self.style.map('Primary.TButton',
                      background=[('active', COLORS["accent_hover"]),
                                 ('disabled', COLORS["bg_light"])])
        
        self.style.configure('Secondary.TButton', 
                            background=COLORS["bg_light"],
                            foreground=COLORS["text"], 
                            font=('Segoe UI', 10),
                            padding=10)
        
        self.style.map('Secondary.TButton',
                      background=[('active', COLORS["bg_medium"])],
                      foreground=[('active', COLORS["text"])])
        
        # Label styles
        self.style.configure('Title.TLabel', 
                            background=COLORS["bg_dark"],
                            foreground=COLORS["accent"], 
                            font=('Segoe UI', 18, 'bold'))
        
        self.style.configure('Subtitle.TLabel', 
                            background=COLORS["bg_dark"],
                            foreground=COLORS["text"], 
                            font=('Segoe UI', 12))
        
        self.style.configure('Info.TLabel', 
                            background=COLORS["bg_dark"],
                            foreground=COLORS["text_dim"], 
                            font=('Segoe UI', 10))
        
        self.style.configure('Header.TLabel', 
                            background=COLORS["bg_dark"],
                            foreground=COLORS["text"], 
                            font=('Segoe UI', 12, 'bold'))
        
        # Entry style - Fixed text color for better visibility
        self.style.configure('TEntry', 
                            fieldbackground=COLORS["bg_light"],
                            foreground='white',  # Changed to white for better contrast
                            insertcolor='white',  # Changed to white for better cursor visibility
                            font=('Segoe UI', 10))
        
        # Add a special style for readonly entries (like generated password display)
        self.style.configure('Readonly.TEntry', 
                            fieldbackground='white',  # White background for generated password
                            foreground='black',        # Black text for better readability
                            insertcolor='black',       # Black cursor
                            font=('Segoe UI', 10))
        
        # Separator style
        self.style.configure('TSeparator', background=COLORS["border"])
        
        # Progressbar style
        self.style.configure("TProgressbar", 
                           troughcolor=COLORS["bg_light"],
                           background=COLORS["accent"])
        
        # Treeview style
        self.style.configure("Treeview",
                           background=COLORS["bg_medium"],
                           foreground=COLORS["text"],
                           rowheight=25,
                           fieldbackground=COLORS["bg_medium"],
                           font=('Segoe UI', 10))
        
        self.style.map('Treeview', 
                     background=[('selected', COLORS["accent"])],
                     foreground=[('selected', 'white')])
        
        # Checkbutton style
        self.style.configure('TCheckbutton',
                           background=COLORS["bg_dark"],
                           foreground=COLORS["text"],
                           font=('Segoe UI', 10))
        
        self.style.map('TCheckbutton',
                     background=[('active', COLORS["bg_dark"])])
        
        # Scale style
        self.style.configure('TScale',
                           background=COLORS["bg_dark"],
                           troughcolor=COLORS["bg_light"],
                           lightcolor=COLORS["accent"],
                           darkcolor=COLORS["accent"])
        
        # Text widget configuration (for tk.Text widgets)
        self.text_config = {
            'bg': COLORS["bg_medium"],
            'fg': COLORS["text"],
            'insertbackground': COLORS["text"],
            'selectbackground': COLORS["accent"],
            'selectforeground': 'white',
            'font': ('Segoe UI', 10),
            'relief': 'flat',
            'borderwidth': 1
        }

class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureShield Password Manager")
        self.root.geometry("1000x800")
        self.root.minsize(800, 600)
        self.root.configure(bg=COLORS["bg_dark"])
        
        # Configure style
        self.style_manager = StyleManager()
        self.style_manager.setup_styles()
        
        # Set up core components
        self.auth = MasterPasswordAuth()
        self.encryption = None
        self.password_store = None
        self.password_generator = PasswordGenerator()
        self.strength_checker = PasswordStrengthChecker()
        self.authenticated = False
        self.current_frame = None
        
        # Set up main container frame
        self.main_frame = ttk.Frame(self.root, padding=0)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Start with authentication
        self.show_auth_screen()
    
    def show_auth_screen(self):
        """Show the login or setup screen"""
        if self.current_frame:
            self.current_frame.destroy()
        
        auth_frame = ttk.Frame(self.main_frame, padding=0)
        auth_frame.pack(fill=tk.BOTH, expand=True)
        self.current_frame = auth_frame
        
        # Center the login content
        content_frame = ttk.Frame(auth_frame)
        content_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        
        # Logo/Title
        title_label = ttk.Label(content_frame, text="SecureShield", style='Title.TLabel')
        title_label.pack(pady=(0, 5))
        
        subtitle_label = ttk.Label(content_frame, text="Password Manager", style='Subtitle.TLabel')
        subtitle_label.pack(pady=(0, 30))
        
        if self.auth.is_configured():
            ttk.Label(content_frame, text="Enter your master password to continue", 
                     style='Info.TLabel').pack(pady=(0, 15))
            
            password_var = tk.StringVar()
            password_entry = ttk.Entry(content_frame, textvariable=password_var, 
                                     show="*", width=35, font=('Segoe UI', 11))
            password_entry.pack(pady=10)
            password_entry.focus_set()
            
            # Fixed: Use consistent styling for error messages
            error_label = ttk.Label(content_frame, text="", 
                                  background=COLORS["bg_dark"],
                                  foreground=COLORS["error"],
                                  font=('Segoe UI', 10))
            error_label.pack(pady=10)
            
            login_btn = ttk.Button(content_frame, text="Login", style="Primary.TButton",
                                 command=lambda: self.login(password_var.get(), error_label))
            login_btn.pack(pady=15)
                       
            # Bind Enter key to login
            password_entry.bind("<Return>", lambda event: self.login(password_var.get(), error_label))
        else:
            ttk.Label(content_frame, text="Welcome to SecureShield Password Manager", 
                     style='Subtitle.TLabel').pack(pady=10)
            ttk.Label(content_frame, text="Let's set up your master password to get started.", 
                     style='Info.TLabel').pack(pady=(0, 20))
            
            password_var = tk.StringVar()
            confirm_var = tk.StringVar()
            
            ttk.Label(content_frame, text="Enter a master password:", 
                     style='Header.TLabel').pack(anchor=tk.W, pady=(15, 5))
            password_entry = ttk.Entry(content_frame, textvariable=password_var, 
                                     show="*", width=35, font=('Segoe UI', 11))
            password_entry.pack(pady=5)
            password_entry.focus_set()
            
            # Add strength indicator
            strength_frame = ttk.Frame(content_frame)
            strength_frame.pack(fill=tk.X, pady=10)
            
            strength_var = tk.StringVar(value="Password strength: Not calculated")
            strength_label = ttk.Label(strength_frame, textvariable=strength_var, style='Info.TLabel')
            strength_label.pack(anchor=tk.W)
            
            strength_bar = ttk.Progressbar(strength_frame, length=300, mode="determinate")
            strength_bar.pack(anchor=tk.W, pady=5)
            
            feedback_var = tk.StringVar()
            # Fixed: Use ttk.Label with style instead of direct foreground to match theme
            feedback_label = ttk.Label(content_frame, textvariable=feedback_var, 
                                     wraplength=350, style='Info.TLabel',  # Use consistent styling
                                     font=('Segoe UI', 9))
            feedback_label.pack(pady=5)
            
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
            
            ttk.Label(content_frame, text="Confirm master password:", 
                     style='Header.TLabel').pack(anchor=tk.W, pady=(15, 5))
            confirm_entry = ttk.Entry(content_frame, textvariable=confirm_var, 
                                    show="*", width=35, font=('Segoe UI', 11))
            confirm_entry.pack(pady=5)
            
            # Fixed: Use ttk.Label with consistent styling for error messages
            error_label = ttk.Label(content_frame, text="", 
                                  background=COLORS["bg_dark"],
                                  foreground=COLORS["error"],
                                  font=('Segoe UI', 10))
            error_label.pack(pady=15)
            
            create_btn = ttk.Button(content_frame, text="Create Master Password", 
                                  style="Primary.TButton",
                                  command=lambda: self.setup(password_var.get(), confirm_var.get(), 
                                                            error_label, strength_bar["value"]))
            create_btn.pack(pady=10)

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
        
        # Create sidebar (matching antivirus style)
        sidebar_frame = ttk.Frame(main_app_frame, width=250)
        sidebar_frame.pack(side=tk.LEFT, fill=tk.Y)
        sidebar_frame.pack_propagate(False)  # Prevent sidebar from shrinking
        
        # Logo section in sidebar
        logo_frame = ttk.Frame(sidebar_frame)
        logo_frame.pack(fill=tk.X, padx=20, pady=30)
        
        logo_label = ttk.Label(logo_frame, text="SecureShield", style='Title.TLabel')
        logo_label.pack()
        
        subtitle_label = ttk.Label(logo_frame, text="Password Manager", style='Info.TLabel')
        subtitle_label.pack(pady=(5, 0))
        
        # Navigation section
        nav_frame = ttk.Frame(sidebar_frame)
        nav_frame.pack(fill=tk.X, padx=10, pady=20)
        
        # Navigation buttons (matching antivirus style)
        nav_buttons = [
            ("View Passwords", self.show_password_list),
            ("Add Password", self.show_add_password),
            ("Generate Password", self.show_generate_password),
            ("Check Strength", self.show_check_strength),
            ("Change Master Password", self.show_change_master_password)  # Added new feature
        ]
        
        for text, command in nav_buttons:
            btn = tk.Button(nav_frame, text=text,
                          font=("Segoe UI", 11), 
                          bg=COLORS["bg_light"], fg=COLORS["text"],
                          activebackground=COLORS["bg_medium"],
                          activeforeground=COLORS["text"],
                          borderwidth=0, padx=20, pady=10,
                          command=command)
            btn.pack(fill=tk.X, pady=3)
        
        # Separator
        ttk.Separator(sidebar_frame, orient='horizontal').pack(fill=tk.X, padx=20, pady=20)
        
        # Logout button
        logout_btn = tk.Button(nav_frame, text="Logout",
                             font=("Segoe UI", 11), 
                             bg=COLORS["error"], fg="white",
                             activebackground="#D73A3A",
                             activeforeground="white",
                             borderwidth=0, padx=20, pady=10,
                             command=self.logout)
        logout_btn.pack(fill=tk.X, pady=3)
        
        # Version info at bottom
        version_frame = ttk.Frame(sidebar_frame)
        version_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=20)
        
        ttk.Label(version_frame, text="Password Manager v1.0", style='Info.TLabel').pack()
        
        # Create content area (matching antivirus style)
        self.content_frame = ttk.Frame(main_app_frame)
        self.content_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0))
        
        # Show password list by default
        self.show_password_list()
    
    def show_password_list(self):
        """Show the list of saved passwords"""
        self.clear_content_frame()
        
        # Header section
        header_frame = ttk.Frame(self.content_frame)
        header_frame.pack(fill=tk.X, padx=30, pady=20)
        
        ttk.Label(header_frame, text="Stored Passwords", style='Title.TLabel').pack(anchor=tk.W)
        ttk.Label(header_frame, text="Manage your saved passwords and credentials", 
                 style='Info.TLabel').pack(anchor=tk.W, pady=5)
        
        # Get all sites
        sites = self.password_store.get_all_sites()
        
        if not sites:
            # Empty state
            empty_frame = ttk.Frame(self.content_frame)
            empty_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=50)
            
            ttk.Label(empty_frame, text="No passwords stored yet", 
                     style='Subtitle.TLabel').pack(anchor=tk.CENTER)
            ttk.Label(empty_frame, text="Click 'Add Password' to get started", 
                     style='Info.TLabel').pack(anchor=tk.CENTER, pady=10)
            
            add_btn = ttk.Button(empty_frame, text="Add Your First Password", 
                               style="Primary.TButton",
                               command=self.show_add_password)
            add_btn.pack(anchor=tk.CENTER, pady=20)
            return
        
        # Table container
        table_frame = ttk.Frame(self.content_frame)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=10)
        
        # Create treeview for passwords
        columns = ("site", "username", "last_modified")
        tree = ttk.Treeview(table_frame, columns=columns, show="headings", 
                           selectmode="browse", height=15)
        tree.heading("site", text="Site/Application")
        tree.heading("username", text="Username")
        tree.heading("last_modified", text="Last Modified")
        tree.column("site", width=250)
        tree.column("username", width=200)
        tree.column("last_modified", width=150)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack the tree and scrollbar
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Add data to tree
        for site in sites:
            entry = self.password_store.get_password(site)
            if entry:
                tree.insert("", tk.END, values=(site, entry["username"], "Recently"))
        
        # Action buttons frame
        action_frame = ttk.Frame(self.content_frame)
        action_frame.pack(fill=tk.X, padx=30, pady=20)
        
        ttk.Button(action_frame, text="View Details", style="Primary.TButton",
                   command=lambda: self.view_password_details(tree)).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Edit", style="Secondary.TButton",
                   command=lambda: self.edit_password(tree)).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Delete", style="Secondary.TButton",
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
        
        # Create details dialog (styled like antivirus)
        details_dialog = tk.Toplevel(self.root)
        details_dialog.title(f"Password Details - {site}")
        details_dialog.geometry("500x400")
        details_dialog.configure(bg=COLORS["bg_dark"])
        details_dialog.transient(self.root)
        details_dialog.grab_set()
        
        # Header
        header_frame = tk.Frame(details_dialog, bg=COLORS["bg_dark"])
        header_frame.pack(fill=tk.X, padx=20, pady=15)
        
        title_label = tk.Label(header_frame, text=f"Details for {site}",
                              bg=COLORS["bg_dark"], fg=COLORS["accent"],
                              font=('Segoe UI', 14, 'bold'))
        title_label.pack(anchor=tk.W)
        
        # Content frame
        content_frame = tk.Frame(details_dialog, bg=COLORS["bg_dark"])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Site
        site_frame = tk.Frame(content_frame, bg=COLORS["bg_dark"])
        site_frame.pack(fill=tk.X, pady=8)
        
        tk.Label(site_frame, text="Site/Application:", 
                bg=COLORS["bg_dark"], fg=COLORS["text"],
                font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        tk.Label(site_frame, text=site,
                bg=COLORS["bg_dark"], fg=COLORS["text"],
                font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=(10, 0))
        
        # Username
        username_frame = tk.Frame(content_frame, bg=COLORS["bg_dark"])
        username_frame.pack(fill=tk.X, pady=8)
        
        tk.Label(username_frame, text="Username:", 
                bg=COLORS["bg_dark"], fg=COLORS["text"],
                font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        tk.Label(username_frame, text=entry["username"],
                bg=COLORS["bg_dark"], fg=COLORS["text"],
                font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=(10, 0))
        
        # Copy username button
        copy_user_btn = tk.Button(username_frame, text="Copy",
                                bg=COLORS["bg_light"], fg=COLORS["text"],
                                activebackground=COLORS["bg_medium"],
                                font=('Segoe UI', 9), padx=10, pady=2, border=0,
                                command=lambda: self.copy_to_clipboard(entry["username"], "Username"))
        copy_user_btn.pack(side=tk.RIGHT)
        
        # Password
        password_frame = tk.Frame(content_frame, bg=COLORS["bg_dark"])
        password_frame.pack(fill=tk.X, pady=8)
        
        tk.Label(password_frame, text="Password:", 
                bg=COLORS["bg_dark"], fg=COLORS["text"],
                font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        
        password_var = tk.StringVar(value="•" * 8)
        show_password = tk.BooleanVar(value=False)
        
        password_label = tk.Label(password_frame, textvariable=password_var,
                                bg=COLORS["bg_dark"], fg=COLORS["text"],
                                font=("Segoe UI", 10))
        password_label.pack(side=tk.LEFT, padx=(10, 0))
        
        def toggle_password():
            if show_password.get():
                password_var.set(entry["password"])
            else:
                password_var.set("•" * 8)
        
        show_check = tk.Checkbutton(password_frame, text="Show", variable=show_password,
                                   bg=COLORS["bg_dark"], fg=COLORS["text"],
                                   activebackground=COLORS["bg_dark"],
                                   selectcolor=COLORS["bg_light"],
                                   font=('Segoe UI', 9),
                                   command=toggle_password)
        show_check.pack(side=tk.RIGHT, padx=5)
        
        # Copy password button
        copy_pass_btn = tk.Button(password_frame, text="Copy",
                                bg=COLORS["accent"], fg="white",
                                activebackground=COLORS["accent_hover"],
                                font=('Segoe UI', 9), padx=10, pady=2, border=0,
                                command=lambda: self.copy_to_clipboard(entry["password"], "Password"))
        copy_pass_btn.pack(side=tk.RIGHT, padx=5)
        
        # Notes
        if entry.get("notes"):
            notes_frame = tk.Frame(content_frame, bg=COLORS["bg_dark"])
            notes_frame.pack(fill=tk.BOTH, expand=True, pady=(15, 10))
            
            tk.Label(notes_frame, text="Notes:", 
                    bg=COLORS["bg_dark"], fg=COLORS["text"],
                    font=("Segoe UI", 10, "bold")).pack(anchor=tk.NW)
            
            notes_text = tk.Text(notes_frame, height=5, width=50, wrap=tk.WORD,
                               **self.style_manager.text_config)
            notes_text.pack(fill=tk.BOTH, expand=True, pady=5)
            notes_text.insert(tk.END, entry.get("notes", ""))
            notes_text.config(state=tk.DISABLED)
        
        # Close button
        button_frame = tk.Frame(content_frame, bg=COLORS["bg_dark"])
        button_frame.pack(fill=tk.X, pady=15)
        
        close_btn = tk.Button(button_frame, text="Close",
                            bg=COLORS["bg_light"], fg=COLORS["text"],
                            activebackground=COLORS["bg_medium"],
                            font=('Segoe UI', 10), padx=20, pady=8, border=0,
                            command=details_dialog.destroy)
        close_btn.pack(side=tk.RIGHT)
    
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
        
        # Header section
        header_frame = ttk.Frame(self.content_frame)
        header_frame.pack(fill=tk.X, padx=30, pady=20)
        
        title = "Edit Password" if edit_site else "Add New Password"
        ttk.Label(header_frame, text=title, style='Title.TLabel').pack(anchor=tk.W)
        
        subtitle = "Update the password details below" if edit_site else "Enter the details for your new password"
        ttk.Label(header_frame, text=subtitle, style='Info.TLabel').pack(anchor=tk.W, pady=5)
        
        # Form container
        form_container = ttk.Frame(self.content_frame)
        form_container.pack(fill=tk.BOTH, expand=True, padx=50, pady=20)
        
        # Site
        site_frame = ttk.Frame(form_container)
        site_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(site_frame, text="Site/Application:", style='Header.TLabel').pack(anchor=tk.W)
        site_var = tk.StringVar(value=edit_site if edit_site else "")
        site_entry = ttk.Entry(site_frame, textvariable=site_var, width=50, font=('Segoe UI', 11))
        site_entry.pack(fill=tk.X, pady=5)
        
        # If editing, disable site field
        if edit_site:
            site_entry.config(state="disabled")
        
        # Username
        username_frame = ttk.Frame(form_container)
        username_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(username_frame, text="Username:", style='Header.TLabel').pack(anchor=tk.W)
        username_var = tk.StringVar(value=edit_entry["username"] if edit_entry else "")
        username_entry = ttk.Entry(username_frame, textvariable=username_var, width=50, font=('Segoe UI', 11))
        username_entry.pack(fill=tk.X, pady=5)
        
        # Password
        password_frame = ttk.Frame(form_container)
        password_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(password_frame, text="Password:", style='Header.TLabel').pack(anchor=tk.W)
        
        password_input_frame = ttk.Frame(password_frame)
        password_input_frame.pack(fill=tk.X, pady=5)
        
        password_var = tk.StringVar(value=edit_entry["password"] if edit_entry else "")
        password_entry = ttk.Entry(password_input_frame, textvariable=password_var, 
                                 show="*", width=40, font=('Segoe UI', 11))
        password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Toggle password visibility
        show_password = tk.BooleanVar(value=False)
        
        def toggle_password():
            password_entry.config(show="" if show_password.get() else "*")
        
        show_check = ttk.Checkbutton(password_input_frame, text="Show", variable=show_password,
                                   command=toggle_password)
        show_check.pack(side=tk.LEFT, padx=10)
        
        # Generate password button
        generate_btn = ttk.Button(password_input_frame, text="Generate", 
                                style="Secondary.TButton",
                                command=lambda: self.generate_for_field(password_var))
        generate_btn.pack(side=tk.LEFT, padx=5)
        
        # Password strength indicator
        strength_frame = ttk.Frame(password_frame)
        strength_frame.pack(fill=tk.X, pady=10)
        
        strength_var = tk.StringVar(value="Password strength: Not calculated")
        ttk.Label(strength_frame, textvariable=strength_var, style='Info.TLabel').pack(anchor=tk.W)
        
        strength_bar = ttk.Progressbar(strength_frame, length=400, mode="determinate")
        strength_bar.pack(anchor=tk.W, pady=5)
        
        feedback_var = tk.StringVar()
        ttk.Label(strength_frame, textvariable=feedback_var, wraplength=500, 
                 style='Info.TLabel').pack(anchor=tk.W, pady=5)
        
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
        
        # Notes
        notes_frame = ttk.Frame(form_container)
        notes_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(notes_frame, text="Notes (optional):", style='Header.TLabel').pack(anchor=tk.W)
        notes_text = tk.Text(notes_frame, height=5, width=50, wrap=tk.WORD,
                           **self.style_manager.text_config)
        notes_text.pack(fill=tk.X, pady=5)
        
        # If editing, populate notes
        if edit_entry and "notes" in edit_entry:
            notes_text.insert(tk.END, edit_entry["notes"])
        
        # Check initial password if editing
        if edit_entry:
            check_password_strength()
        
        # Buttons
        button_frame = ttk.Frame(form_container)
        button_frame.pack(fill=tk.X, pady=20)
        
        save_text = "Update Password" if edit_site else "Save Password"
        
        save_btn = ttk.Button(button_frame, text=save_text, style="Primary.TButton",
                            command=lambda: self.save_password(
                                site_var.get(), 
                                username_var.get(), 
                                password_var.get(), 
                                notes_text.get("1.0", tk.END).strip(),
                                edit_site
                            ))
        save_btn.pack(side=tk.LEFT)
        
        cancel_btn = ttk.Button(button_frame, text="Cancel", style="Secondary.TButton",
                              command=self.show_password_list)
        cancel_btn.pack(side=tk.LEFT, padx=10)
    
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
        
        # Header section
        header_frame = ttk.Frame(self.content_frame)
        header_frame.pack(fill=tk.X, padx=30, pady=20)
        
        ttk.Label(header_frame, text="Password Generator", style='Title.TLabel').pack(anchor=tk.W)
        ttk.Label(header_frame, text="Generate secure passwords with custom options", 
                 style='Info.TLabel').pack(anchor=tk.W, pady=5)
        
        # Main container
        main_container = ttk.Frame(self.content_frame)
        main_container.pack(fill=tk.BOTH, expand=True, padx=50, pady=20)
        
        # Options section
        options_section = ttk.Frame(main_container)
        options_section.pack(fill=tk.X, pady=20)
        
        ttk.Label(options_section, text="Generation Options", style='Subtitle.TLabel').pack(anchor=tk.W, pady=(0, 15))
        
        # Length
        length_frame = ttk.Frame(options_section)
        length_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(length_frame, text="Password Length:", style='Header.TLabel').pack(anchor=tk.W)
        
        length_var = tk.IntVar(value=16)
        length_control_frame = ttk.Frame(length_frame)
        length_control_frame.pack(fill=tk.X, pady=5)
        
        length_scale = ttk.Scale(length_control_frame, from_=8, to=64, variable=length_var, length=300)
        length_scale.pack(side=tk.LEFT)
        
        # Fixed: Display integer value only, not decimals
        length_display_var = tk.StringVar(value="16")
        length_label = ttk.Label(length_control_frame, textvariable=length_display_var, width=5,
                               style='Header.TLabel')
        length_label.pack(side=tk.LEFT, padx=15)
        
        # Update display when scale changes
        def update_length_display(*args):
            length_display_var.set(str(int(length_var.get())))
        
        length_var.trace_add("write", update_length_display)
        
        # Character options
        char_frame = ttk.Frame(options_section)
        char_frame.pack(fill=tk.X, pady=15)
        
        ttk.Label(char_frame, text="Character Types:", style='Header.TLabel').pack(anchor=tk.W, pady=(0, 10))
        
        char_options_frame = ttk.Frame(char_frame)
        char_options_frame.pack(fill=tk.X)
        
        uppercase_var = tk.BooleanVar(value=True)
        lowercase_var = tk.BooleanVar(value=True)
        digits_var = tk.BooleanVar(value=True)
        special_var = tk.BooleanVar(value=True)
        exclude_similar_var = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(char_options_frame, text="Uppercase Letters (A-Z)", 
                        variable=uppercase_var).pack(anchor=tk.W, pady=3)
        ttk.Checkbutton(char_options_frame, text="Lowercase Letters (a-z)", 
                        variable=lowercase_var).pack(anchor=tk.W, pady=3)
        ttk.Checkbutton(char_options_frame, text="Digits (0-9)", 
                        variable=digits_var).pack(anchor=tk.W, pady=3)
        ttk.Checkbutton(char_options_frame, text="Special Characters (!@#$%^&*)", 
                        variable=special_var).pack(anchor=tk.W, pady=3)
        ttk.Checkbutton(char_options_frame, text="Exclude Similar Characters (I, l, 1, O, 0)", 
                        variable=exclude_similar_var).pack(anchor=tk.W, pady=3)
        
        # Generate button
        generate_btn = ttk.Button(options_section, text="Generate Password", style="Primary.TButton",
                                command=lambda: self.generate_password_action(
                                    int(length_var.get()),  # Ensure integer value
                                    uppercase_var.get(),
                                    lowercase_var.get(),
                                    digits_var.get(),
                                    special_var.get(),
                                    exclude_similar_var.get()
                                ))
        generate_btn.pack(anchor=tk.W, pady=20)
        
        # Result section
        result_section = ttk.Frame(main_container)
        result_section.pack(fill=tk.X, pady=20)
        
        ttk.Label(result_section, text="Generated Password", style='Subtitle.TLabel').pack(anchor=tk.W, pady=(0, 10))
        
        result_frame = ttk.Frame(result_section)
        result_frame.pack(fill=tk.X)
        
        # Initialize password result variable as instance variable with better styling
        self.password_result_var = tk.StringVar(value="Click 'Generate Password' to create a new password")
        result_entry = ttk.Entry(result_frame, textvariable=self.password_result_var, 
                               width=60, font=("Courier", 11), state="readonly",
                               style="Readonly.TEntry")  # Use the new readonly style
        result_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Copy button
        copy_btn = ttk.Button(result_frame, text="Copy", style="Secondary.TButton",
                            command=lambda: self.copy_to_clipboard(self.password_result_var.get(), "Password"))
        copy_btn.pack(side=tk.LEFT, padx=10)
        
        # Password strength display
        strength_section = ttk.Frame(main_container)
        strength_section.pack(fill=tk.X, pady=20)
        
        # Initialize strength variables as instance variables
        self.strength_var = tk.StringVar(value="Password strength will appear here")
        ttk.Label(strength_section, textvariable=self.strength_var, style='Info.TLabel').pack(anchor=tk.W)
        
        self.strength_bar = ttk.Progressbar(strength_section, length=500, mode="determinate")
        self.strength_bar.pack(anchor=tk.W, pady=5)
        
        self.feedback_var = tk.StringVar()
        ttk.Label(strength_section, textvariable=self.feedback_var, wraplength=600,
                 style='Info.TLabel').pack(anchor=tk.W, pady=5)
  
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
        
        # Header section
        header_frame = ttk.Frame(self.content_frame)
        header_frame.pack(fill=tk.X, padx=30, pady=20)
        
        ttk.Label(header_frame, text="Password Strength Checker", style='Title.TLabel').pack(anchor=tk.W)
        ttk.Label(header_frame, text="Analyze the security strength of your passwords", 
                 style='Info.TLabel').pack(anchor=tk.W, pady=5)
        
        # Main container
        main_container = ttk.Frame(self.content_frame)
        main_container.pack(fill=tk.BOTH, expand=True, padx=50, pady=30)
        
        # Input section
        input_section = ttk.Frame(main_container)
        input_section.pack(fill=tk.X, pady=20)
        
        ttk.Label(input_section, text="Enter password to analyze:", style='Subtitle.TLabel').pack(anchor=tk.W, pady=(0, 10))
        
        password_input_frame = ttk.Frame(input_section)
        password_input_frame.pack(fill=tk.X, pady=10)
        
        password_var = tk.StringVar()
        password_entry = ttk.Entry(password_input_frame, textvariable=password_var, 
                                 show="*", width=50, font=('Segoe UI', 11))
        password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Show/hide password
        show_var = tk.BooleanVar(value=False)
        
        def toggle_visibility():
            password_entry.config(show="" if show_var.get() else "*")
        
        show_check = ttk.Checkbutton(password_input_frame, text="Show password", 
                                   variable=show_var, command=toggle_visibility)
        show_check.pack(side=tk.LEFT, padx=15)
        
        # Remove the manual check button since we're doing real-time checking
        
        # Results section
        results_section = ttk.Frame(main_container)
        results_section.pack(fill=tk.X, pady=30)
        
        ttk.Label(results_section, text="Analysis Results", style='Subtitle.TLabel').pack(anchor=tk.W, pady=(0, 15))
        
        self.strength_result_var = tk.StringVar(value="Enter a password to see analysis")
        ttk.Label(results_section, textvariable=self.strength_result_var, 
                 style='Header.TLabel').pack(anchor=tk.W)
        
        self.strength_result_bar = ttk.Progressbar(results_section, length=500, mode="determinate")
        self.strength_result_bar.pack(anchor=tk.W, pady=10)
        
        self.feedback_result_var = tk.StringVar()
        feedback_label = ttk.Label(results_section, textvariable=self.feedback_result_var, 
                                 wraplength=600, style='Info.TLabel')
        feedback_label.pack(anchor=tk.W, pady=10)
        
        # Real-time checking
        def check_on_change(*args):
            password = password_var.get()
            if password:
                self.check_password_strength_action(password)
            else:
                self.strength_result_var.set("Enter a password to see analysis")
                self.strength_result_bar["value"] = 0
                self.feedback_result_var.set("")
        
        password_var.trace_add("write", check_on_change)

    def check_password_strength_action(self, password):
        """Check the strength of a given password"""
        if not password:
            return
        
        score, category, feedback = self.strength_checker.check_strength(password)
        
        self.strength_result_var.set(f"Password strength: {category} ({score}/100)")
        self.strength_result_bar["value"] = score
        self.feedback_result_var.set(feedback)

    def show_change_master_password(self):
        """Show the change master password screen"""
        self.clear_content_frame()
        
        # Header section
        header_frame = ttk.Frame(self.content_frame)
        header_frame.pack(fill=tk.X, padx=30, pady=20)
        
        ttk.Label(header_frame, text="Change Master Password", style='Title.TLabel').pack(anchor=tk.W)
        ttk.Label(header_frame, text="Update your master password for enhanced security", 
                 style='Info.TLabel').pack(anchor=tk.W, pady=5)
        
        # Main container
        main_container = ttk.Frame(self.content_frame)
        main_container.pack(fill=tk.BOTH, expand=True, padx=50, pady=30)
        
        # Warning section
        warning_frame = ttk.Frame(main_container)
        warning_frame.pack(fill=tk.X, pady=(0, 20))
        
        warning_label = ttk.Label(warning_frame, 
                                text="⚠️ Important: Changing your master password will require you to re-encrypt all stored passwords.",
                                style='Info.TLabel', wraplength=600)
        warning_label.pack(anchor=tk.W)
        
        # Form section
        form_frame = ttk.Frame(main_container)
        form_frame.pack(fill=tk.X, pady=20)
        
        # Current password
        current_frame = ttk.Frame(form_frame)
        current_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(current_frame, text="Current Master Password:", style='Header.TLabel').pack(anchor=tk.W)
        current_password_var = tk.StringVar()
        current_password_entry = ttk.Entry(current_frame, textvariable=current_password_var, 
                                         show="*", width=50, font=('Segoe UI', 11))
        current_password_entry.pack(fill=tk.X, pady=5)
        current_password_entry.focus_set()
        
        # New password
        new_frame = ttk.Frame(form_frame)
        new_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(new_frame, text="New Master Password:", style='Header.TLabel').pack(anchor=tk.W)
        new_password_var = tk.StringVar()
        new_password_entry = ttk.Entry(new_frame, textvariable=new_password_var, 
                                     show="*", width=50, font=('Segoe UI', 11))
        new_password_entry.pack(fill=tk.X, pady=5)
        
        # New password strength indicator
        strength_frame = ttk.Frame(new_frame)
        strength_frame.pack(fill=tk.X, pady=10)
        
        strength_var = tk.StringVar(value="Password strength: Not calculated")
        ttk.Label(strength_frame, textvariable=strength_var, style='Info.TLabel').pack(anchor=tk.W)
        
        strength_bar = ttk.Progressbar(strength_frame, length=400, mode="determinate")
        strength_bar.pack(anchor=tk.W, pady=5)
        
        feedback_var = tk.StringVar()
        ttk.Label(strength_frame, textvariable=feedback_var, wraplength=500, 
                 style='Info.TLabel').pack(anchor=tk.W, pady=5)
        
        # Update strength when new password changes
        def check_new_password_strength(*args):
            password = new_password_var.get()
            if password:
                score, category, feedback = self.strength_checker.check_strength(password)
                strength_var.set(f"Password strength: {category} ({score}/100)")
                strength_bar["value"] = score
                feedback_var.set(feedback)
            else:
                strength_var.set("Password strength: Not calculated")
                strength_bar["value"] = 0
                feedback_var.set("")
        
        new_password_var.trace_add("write", check_new_password_strength)
        
        # Confirm new password
        confirm_frame = ttk.Frame(form_frame)
        confirm_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(confirm_frame, text="Confirm New Master Password:", style='Header.TLabel').pack(anchor=tk.W)
        confirm_password_var = tk.StringVar()
        confirm_password_entry = ttk.Entry(confirm_frame, textvariable=confirm_password_var, 
                                         show="*", width=50, font=('Segoe UI', 11))
        confirm_password_entry.pack(fill=tk.X, pady=5)
        
        # Error/Status label
        status_label = ttk.Label(form_frame, text="", 
                               background=COLORS["bg_dark"],
                               foreground=COLORS["error"],
                               font=('Segoe UI', 10))
        status_label.pack(pady=15)
        
        # Buttons
        button_frame = ttk.Frame(form_frame)
        button_frame.pack(fill=tk.X, pady=20)
        
        change_btn = ttk.Button(button_frame, text="Change Master Password", style="Primary.TButton",
                              command=lambda: self.change_master_password(
                                  current_password_var.get(),
                                  new_password_var.get(),
                                  confirm_password_var.get(),
                                  status_label,
                                  strength_bar["value"]
                              ))
        change_btn.pack(side=tk.LEFT)
        
        cancel_btn = ttk.Button(button_frame, text="Cancel", style="Secondary.TButton",
                              command=self.show_password_list)
        cancel_btn.pack(side=tk.LEFT, padx=10)

    def change_master_password(self, current_password, new_password, confirm_password, status_label, strength_score):
        """Change the master password"""
        # Validate inputs
        if not current_password:
            status_label.config(text="Current password cannot be empty")
            return
        
        if not new_password:
            status_label.config(text="New password cannot be empty")
            return
        
        if not confirm_password:
            status_label.config(text="Please confirm the new password")
            return
        
        # Verify current password
        if not self.auth.authenticate(current_password):
            status_label.config(text="Current password is incorrect")
            return
        
        # Check if new password is different
        if current_password == new_password:
            status_label.config(text="New password must be different from current password")
            return
        
        # Validate new password
        if new_password != confirm_password:
            status_label.config(text="New passwords don't match")
            return
        
        # Check password strength
        if strength_score < 40:
            status_label.config(text="New password is too weak. Please choose a stronger password.")
            return
        
        try:
            # Get all current passwords before changing master password
            all_sites = self.password_store.get_all_sites()
            all_passwords = {}
            
            for site in all_sites:
                entry = self.password_store.get_password(site)
                if entry:
                    all_passwords[site] = entry
            
            # Change the master password
            self.auth.change_master_password(current_password, new_password)
            
            # Re-initialize encryption with new key
            self.encryption = PasswordEncryption(self.auth.get_encryption_key())
            
            # Re-initialize password store
            self.password_store = PasswordStore(encryption=self.encryption)
            
            # Re-encrypt and save all passwords with new master password
            for site, entry in all_passwords.items():
                self.password_store.add_password(
                    site, 
                    entry["username"], 
                    entry["password"], 
                    entry.get("notes", "")
                )
            
            messagebox.showinfo("Success", "Master password changed successfully!\nAll stored passwords have been re-encrypted.")
            self.show_password_list()
            
        except Exception as e:
            status_label.config(text=f"Failed to change password: {str(e)}")
    
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
    
    root.mainloop()

if __name__ == "__main__":
    main()