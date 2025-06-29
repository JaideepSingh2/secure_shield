import platform
import subprocess

class Notifier:
    def __init__(self):
        """Initialize the notifier based on platform"""
        self.os_type = platform.system().lower()
        
    def send_notification(self, title, message, urgency="normal"):
        return False
            
    def _linux_notify(self, title, message, urgency):
        """Send notification on Linux using notify-send"""
        try:
            urgency_flag = f"--urgency={urgency}"
            subprocess.run(["notify-send", urgency_flag, title, message])
            return True
        except Exception as e:
            print(f"Notification error: {e}")
            return False
            
    def _windows_notify(self, title, message, urgency):
        """Send notification on Windows using PowerShell"""
        try:
            # PowerShell script to show notification
            ps_script = f"""
            [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
            [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
            
            $APP_ID = 'PythonFirewall'
            
            $template = @"
            <toast>
                <visual>
                    <binding template="ToastText02">
                        <text id="1">{title}</text>
                        <text id="2">{message}</text>
                    </binding>
                </visual>
            </toast>
            "@
            
            $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
            $xml.LoadXml($template)
            $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($APP_ID).Show($toast)
            """
            
            subprocess.run(["powershell", "-Command", ps_script], 
                          shell=True, check=True)
            return True
        except Exception as e:
            print(f"Notification error: {e}")
            return False
            
    def _macos_notify(self, title, message, urgency):
        """Send notification on macOS using osascript"""
        try:
            apple_script = f'display notification "{message}" with title "{title}"'
            subprocess.run(["osascript", "-e", apple_script])
            return True
        except Exception as e:
            print(f"Notification error: {e}")
            return False
            
    def notify_blocked_connection(self, src_ip, dst_ip, port, protocol):
        """Send a notification about blocked connection"""
        title = "Firewall Alert: Connection Blocked"
        message = f"Blocked {protocol} connection from {src_ip} to {dst_ip}:{port}"
        self.send_notification(title, message, urgency="critical")
        
    def notify_firewall_status(self, status):
        """Send a notification about firewall status change"""
        title = "Firewall Status"
        message = f"Firewall is now {status}"
        self.send_notification(title, message)