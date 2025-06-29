import os
import platform
import ctypes
import subprocess

class PermissionChecker:
    @staticmethod
    def is_admin():
        """Check if the application is running with admin/root privileges"""
        system = platform.system().lower()
        
        # Linux
        if system == 'linux':
            return os.geteuid() == 0
            
        # Windows
        elif system == 'windows':
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False
                
        # macOS
        elif system == 'darwin':
            return os.geteuid() == 0
        
        # Other systems - assume not admin
        return False
    
    @staticmethod
    def request_admin():
        """Try to restart the application with elevated privileges"""
        system = platform.system().lower()
        
        # Linux
        if system == 'linux':
            try:
                script_path = os.path.dirname(os.path.abspath(__file__))
                main_script = os.path.join(os.path.dirname(script_path), "main.py")
                
                # Use the run_firewall.sh script instead of direct pkexec
                run_script = os.path.join(os.path.dirname(script_path), "run_firewall.sh")
                if os.path.exists(run_script):
                    subprocess.Popen(['bash', run_script])
                else:
                    subprocess.Popen(['pkexec', 'python3', main_script])
                return True
            except Exception as e:
                print(f"Error requesting admin: {e}")
                return False
                
        # Windows
        elif system == 'windows':
            try:
                script_path = os.path.dirname(os.path.abspath(__file__))
                main_script = os.path.join(os.path.dirname(script_path), "main.py")
                ctypes.windll.shell32.ShellExecuteW(None, "runas", "python", main_script, None, 1)
                return True
            except Exception as e:
                print(f"Error requesting admin: {e}")
                return False
                
        # macOS
        elif system == 'darwin':
            try:
                script_path = os.path.dirname(os.path.abspath(__file__))
                main_script = os.path.join(os.path.dirname(script_path), "main.py")
                subprocess.Popen(['osascript', '-e', 
                            f'do shell script "python3 {main_script}" with administrator privileges'])
                return True
            except Exception as e:
                print(f"Error requesting admin: {e}")
                return False
                
        return False