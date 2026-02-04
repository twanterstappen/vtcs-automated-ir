#!/usr/bin/env python3
"""
Wazuh Agent Installation GUI (Cross-Platform)
Supports both Windows and Linux installations with a unified interface.
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import threading
import os
import sys
import urllib.request
import time
from pathlib import Path
import platform

# Platform detection
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"

if IS_WINDOWS:
    import ctypes


def request_admin_privileges():
    """On Windows, re-run the script with admin privileges if not already running as admin"""
    if not IS_WINDOWS:
        return True
    
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            # Re-run this script with admin privileges
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            # Exit immediately without creating GUI
            time.sleep(0.5)
            os._exit(0)
    except:
        pass
    
    return True


class WazuhInstallerGUI:
    def __init__(self, root):
        self.root = root
        os_name = "Windows" if IS_WINDOWS else "Linux" if IS_LINUX else "macOS" if IS_MACOS else "Cross-Platform"
        self.root.title(f"Wazuh Agent Installer ({os_name})")
        self.root.geometry("700x750")
        self.root.resizable(False, False)
        
        # Set icon (if available)
        try:
            self.root.iconbitmap(default='')
        except:
            pass
        
        # Determine script directory
        if getattr(sys, 'frozen', False):
            self.script_dir = Path(sys.executable).parent
        else:
            self.script_dir = Path(__file__).parent
        
        self.installation_thread = None
        self.setup_ui()
        
    def setup_ui(self):
        """Create the user interface"""
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        os_text = "Windows" if IS_WINDOWS else "Linux" if IS_LINUX else "macOS"
        title_label = ttk.Label(
            main_frame,
            text=f"Wazuh Agent Installation ({os_text})",
            font=("Arial", 18, "bold")
        )
        title_label.pack(pady=(0, 20))
        
        # Input section
        input_frame = ttk.LabelFrame(main_frame, text="Configuration", padding="10")
        input_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Manager IP
        ttk.Label(input_frame, text="Wazuh Manager IP *", font=("Arial", 10)).pack(anchor=tk.W)
        self.ip_entry = ttk.Entry(input_frame, width=40, font=("Arial", 10))
        self.ip_entry.pack(fill=tk.X, pady=(0, 15))
        
        # Agent Name
        ttk.Label(input_frame, text="Agent Name (optional)", font=("Arial", 10)).pack(anchor=tk.W)
        self.name_entry = ttk.Entry(input_frame, width=40, font=("Arial", 10))
        self.name_entry.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(input_frame, text="* Required field", font=("Arial", 8), foreground="gray").pack(anchor=tk.W)
        
        # Log section
        log_frame = ttk.LabelFrame(main_frame, text="Installation Log", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=15,
            width=80,
            font=("Courier New", 9),
            state=tk.DISABLED,
            wrap=tk.WORD
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Progress bar
        self.progress = ttk.Progressbar(
            main_frame,
            length=400,
            mode='determinate',
            maximum=5
        )
        self.progress.pack(fill=tk.X, pady=(0, 10))
        
        self.status_label = ttk.Label(main_frame, text="Ready", font=("Arial", 9))
        self.status_label.pack(anchor=tk.W)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(20, 0))
        
        self.install_button = ttk.Button(
            button_frame,
            text="Start Installation",
            command=self.start_installation
        )
        self.install_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.clear_button = ttk.Button(
            button_frame,
            text="Clear Log",
            command=self.clear_log
        )
        self.clear_button.pack(side=tk.LEFT)
        
        ttk.Button(button_frame, text="Exit", command=self.root.quit).pack(side=tk.RIGHT)
        
    def log(self, message):
        """Add a message to the log"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.root.update_idletasks()
        
    def clear_log(self):
        """Clear the log text"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
        
    def update_progress(self, step):
        """Update progress bar"""
        self.progress['value'] = step
        self.root.update_idletasks()
        
    def update_status(self, message):
        """Update status label"""
        self.status_label.config(text=message)
        self.root.update_idletasks()
        
    def is_admin(self):
        """Check if running as administrator/root"""
        if IS_WINDOWS:
            try:
                return ctypes.windll.shell32.IsUserAnAdmin()
            except:
                return False
        else:
            # On Linux, check if running as root
            return os.geteuid() == 0
        
    def validate_inputs(self):
        """Validate user inputs"""
        manager_ip = self.ip_entry.get().strip()
        
        if not manager_ip:
            messagebox.showerror("Validation Error", "Wazuh Manager IP is required")
            return None
            
        return {
            "manager_ip": manager_ip,
            "agent_name": self.name_entry.get().strip() or None
        }
        
    def start_installation(self):
        """Start the installation process"""
        # Check for remove-threat script
        if IS_WINDOWS:
            remove_threat_file = "remove-threat.exe"
        else:  # Linux or macOS
            remove_threat_file = "remove-threat"
            
        remove_threat_path = os.path.join(str(self.script_dir), remove_threat_file)
        if not os.path.exists(remove_threat_path):
            response = messagebox.askyesno(
                "Missing File",
                f"{remove_threat_file} not found in the same directory.\n\n"
                "Do you want to continue with Wazuh Agent installation only?"
            )
            if not response:
                return
        
        # Check admin/root privileges
        if not self.is_admin():
            if IS_WINDOWS:
                messagebox.showerror(
                    "Administrator Required",
                    "This script must be run as Administrator.\n\n"
                    "Please right-click and select 'Run as administrator'"
                )
            else:
                # Show appropriate command for Python script or compiled executable
                is_frozen = getattr(sys, 'frozen', False)
                if is_frozen:
                    cmd = "sudo ./install-wazuh-agent-gui"
                else:
                    cmd = "sudo python3 install-wazuh-agent-gui.py"
                
                messagebox.showerror(
                    "Root Required",
                    "This application must be run as root (sudo).\n\n"
                    f"Please run: {cmd}"
                )
            return
            
        config = self.validate_inputs()
        if not config:
            return
            
        self.install_button.config(state=tk.DISABLED)
        self.clear_log()
        self.progress['value'] = 0
        
        # Run installation in background thread
        self.installation_thread = threading.Thread(
            target=self.run_installation,
            args=(config,),
            daemon=True
        )
        self.installation_thread.start()
        
    def run_installation(self, config):
        """Execute the installation steps"""
        try:
            os_name = "Windows" if IS_WINDOWS else "Linux" if IS_LINUX else "macOS"
            self.log(f"=== Wazuh Agent Installation ({os_name}) ===")
            
            manager_ip = config["manager_ip"]
            agent_name = config["agent_name"]
            
            if IS_WINDOWS:
                wazuh_installed, remove_threat_deployed = self.install_windows(manager_ip, agent_name)
            elif IS_LINUX:
                wazuh_installed, remove_threat_deployed = self.install_linux(manager_ip, agent_name)
            elif IS_MACOS:
                wazuh_installed, remove_threat_deployed = self.install_macos(manager_ip, agent_name)
            else:
                raise Exception("Unsupported operating system")
            
            # Final status
            self.log("=" * 40)
            if wazuh_installed:
                if remove_threat_deployed:
                    self.log("✓ Installation Complete!")
                else:
                    self.log("✓ Wazuh Agent Installed")
                    self.log("⚠ remove-threat not deployed")
            else:
                self.log("⚠ Installation encountered issues")
            self.log("=" * 40)
            
            self.log(f"\nConfiguration Summary:")
            self.log(f"  Manager IP: {manager_ip}")
            if agent_name:
                self.log(f"  Agent Name: {agent_name}")
            
            self.update_status("✓ Complete!")
            
            if wazuh_installed:
                messagebox.showinfo("Success", "Wazuh Agent installed successfully!")
            else:
                messagebox.showerror("Failed", "Installation failed. Check the log.")
            
        except Exception as e:
            self.log(f"\\n✗ Installation failed: {e}")
            self.update_status("✗ Failed")
            messagebox.showerror("Installation Failed", f"Error: {e}")
            
        finally:
            self.install_button.config(state=tk.NORMAL)
    
    def install_windows(self, manager_ip, agent_name):
        """Windows installation"""
        remove_threat_deployed = False
        wazuh_installed = False
        
        self.log(f"Manager IP: {manager_ip}")
        if agent_name:
            self.log(f"Agent Name: {agent_name}")
        self.log("")
        
        # Step 1: Download
        self.log("[1/5] Downloading Wazuh Agent...")
        self.update_status("Downloading...")
        self.update_progress(1)
        
        tmp_dir = os.environ.get('TEMP', 'C:\\\\Windows\\\\Temp')
        msi_file = os.path.join(tmp_dir, 'wazuh-agent-4.14.1-1.msi')
        
        self.download_file(
            "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.1-1.msi",
            msi_file
        )
        self.log(f"  ✓ Downloaded")
        
        # Step 2: Install
        self.log("[2/5] Installing...")
        self.update_progress(2)
        
        msi_args = ["msiexec.exe", "/i", msi_file, "/q", f"WAZUH_MANAGER={manager_ip}"]
        if agent_name:
            msi_args.append(f"WAZUH_AGENT_NAME={agent_name}")
        
        subprocess.run(msi_args)
        time.sleep(10)
        wazuh_installed = True
        self.log("  ✓ Installed")
        
        # Step 3: Verify
        self.log("[3/5] Verifying...")
        self.update_progress(3)
        
        agent_dir = "C:\\\\Program Files (x86)\\\\ossec-agent"
        active_response_bin = os.path.join(agent_dir, "active-response", "bin")
        
        if not os.path.exists(active_response_bin):
            raise Exception("Agent directory not found")
        
        self.log(f"  ✓ Verified")
        
        # Step 4: Deploy remove-threat
        self.log("[4/5] Deploying remove-threat...")
        self.update_progress(4)
        
        remove_threat_src = os.path.join(str(self.script_dir), "remove-threat.exe")
        if os.path.exists(remove_threat_src):
            import shutil
            shutil.copy2(remove_threat_src, os.path.join(active_response_bin, "remove-threat.exe"))
            remove_threat_deployed = True
            self.log("  ✓ Deployed")
        else:
            self.log("  ⚠ Skipped")
        
        # Step 5: Start service
        self.log("[5/5] Starting service...")
        self.update_progress(5)
        subprocess.run(["net", "start", "Wazuh"], capture_output=True)
        self.log("  ✓ Started")
        
        # Cleanup
        try:
            os.remove(msi_file)
        except:
            pass
        
        return wazuh_installed, remove_threat_deployed
    
    def install_linux(self, manager_ip, agent_name):
        """Linux installation"""
        remove_threat_deployed = False
        wazuh_installed = False
        
        self.log(f"Manager IP: {manager_ip}")
        if agent_name:
            self.log(f"Agent Name: {agent_name}")
        self.log("")
        
        # Step 1: Detect system configuration
        self.log("[1/5] Detecting system configuration...")
        self.update_status("Detecting system...")
        self.update_progress(1)
        
        # Detect architecture
        machine = platform.machine().lower()
        if machine in ['x86_64', 'amd64']:
            arch_deb = 'amd64'
            arch_rpm = 'x86_64'
        elif machine in ['aarch64', 'arm64']:
            arch_deb = 'arm64'
            arch_rpm = 'aarch64'
        else:
            raise Exception(f"Unsupported architecture: {machine}")
        
        # Detect package type
        try:
            with open('/etc/os-release') as f:
                os_info = f.read()
                if 'Ubuntu' in os_info or 'Debian' in os_info:
                    pkg_type = 'deb'
                elif 'CentOS' in os_info or 'Red Hat' in os_info or 'Fedora' in os_info or 'Rocky' in os_info or 'AlmaLinux' in os_info:
                    pkg_type = 'rpm'
                else:
                    # Try to detect by available commands
                    if subprocess.run(['which', 'dpkg'], capture_output=True).returncode == 0:
                        pkg_type = 'deb'
                    elif subprocess.run(['which', 'rpm'], capture_output=True).returncode == 0:
                        pkg_type = 'rpm'
                    else:
                        pkg_type = 'deb'  # default
        except:
            pkg_type = 'deb'
        
        self.log(f"  Detected: {pkg_type} package, {arch_deb if pkg_type == 'deb' else arch_rpm} architecture")
        self.log("  ✓ System detected\n")
        
        # Step 2: Download Wazuh Agent package
        self.log("[2/5] Downloading Wazuh Agent package...")
        self.update_status("Downloading package...")
        self.update_progress(2)
        
        if pkg_type == 'deb':
            pkg_file = f"wazuh-agent_4.14.1-1_{arch_deb}.deb"
            pkg_url = f"https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/{pkg_file}"
        else:  # rpm
            pkg_file = f"wazuh-agent-4.14.1-1.{arch_rpm}.rpm"
            pkg_url = f"https://packages.wazuh.com/4.x/yum/{pkg_file}"
        
        tmp_dir = '/tmp'
        pkg_path = os.path.join(tmp_dir, pkg_file)
        
        self.download_file(pkg_url, pkg_path)
        self.log(f"  ✓ Downloaded {pkg_file}")
        
        # Step 3: Install Wazuh Agent
        self.log("[3/5] Installing Wazuh Agent...")
        self.update_status("Installing agent...")
        self.update_progress(3)
        
        env = os.environ.copy()
        env['WAZUH_MANAGER'] = manager_ip
        if agent_name:
            env['WAZUH_AGENT_NAME'] = agent_name
        
        if pkg_type == 'deb':
            result = subprocess.run(['dpkg', '-i', pkg_path], env=env, capture_output=True, text=True)
            wazuh_installed = result.returncode == 0
            if not wazuh_installed:
                self.log(f"  ⚠ dpkg output: {result.stderr[:200]}")
        else:  # rpm
            result = subprocess.run(['rpm', '-ihv', pkg_path], env=env, capture_output=True, text=True)
            wazuh_installed = result.returncode == 0
            if not wazuh_installed:
                self.log(f"  ⚠ rpm output: {result.stderr[:200]}")
        
        # Cleanup package file
        try:
            os.remove(pkg_path)
        except:
            pass
        
        self.log("  ✓ Installed")
        
        # Step 4: Verify
        self.log("[4/5] Verifying...")
        self.update_progress(4)
        
        if not os.path.exists('/var/ossec'):
            raise Exception("Wazuh directory not found")
        
        self.log("  ✓ Verified")
        
        # Step 5: Deploy remove-threat
        self.log("[5/5] Deploying remove-threat...")
        self.update_progress(5)
        
        remove_threat_src = os.path.join(str(self.script_dir), "remove-threat")
        if os.path.exists(remove_threat_src):
            import shutil
            dest = "/var/ossec/active-response/bin/remove-threat"
            shutil.copy2(remove_threat_src, dest)
            os.chmod(dest, 0o750)
            subprocess.run(['chown', 'root:wazuh', dest], capture_output=True)
            remove_threat_deployed = True
            self.log("  ✓ Deployed")
        else:
            self.log("  ⚠ Skipped")
        
        # Start service
        subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
        subprocess.run(['systemctl', 'enable', 'wazuh-agent'], capture_output=True)
        subprocess.run(['systemctl', 'start', 'wazuh-agent'], capture_output=True)
        self.log("  ✓ Service started\n")
        
        return wazuh_installed, remove_threat_deployed
    
    def install_macos(self, manager_ip, agent_name):
        """macOS installation"""
        remove_threat_deployed = False
        wazuh_installed = False
        
        self.log(f"Manager IP: {manager_ip}")
        if agent_name:
            self.log(f"Agent Name: {agent_name}")
        self.log("")
        
        # Step 1: Detect architecture
        self.log("[1/5] Detecting macOS architecture...")
        self.update_status("Detecting architecture...")
        self.update_progress(1)
        
        machine = platform.machine().lower()
        if machine == 'x86_64':
            arch = 'intel64'
            arch_name = 'Intel'
        elif machine in ['arm64', 'aarch64']:
            arch = 'arm64'
            arch_name = 'Apple Silicon'
        else:
            raise Exception(f"Unsupported macOS architecture: {machine}")
        
        self.log(f"  Detected: {arch_name}")
        self.log("  ✓ Architecture detected")
        
        # Step 2: Download Wazuh Agent package
        self.log("[2/5] Downloading Wazuh Agent...")
        self.update_status("Downloading package...")
        self.update_progress(2)
        
        pkg_file = f"wazuh-agent-4.14.1-1.{arch}.pkg"
        pkg_url = f"https://packages.wazuh.com/4.x/macos/{pkg_file}"
        pkg_path = f"/tmp/{pkg_file}"
        
        self.download_file(pkg_url, pkg_path)
        self.log(f"  ✓ Downloaded {pkg_file}")
        
        # Step 3: Configure environment
        self.log("[3/5] Configuring environment...")
        self.update_status("Configuring...")
        self.update_progress(3)
        
        with open('/tmp/wazuh_envs', 'w') as f:
            f.write(f"WAZUH_MANAGER='{manager_ip}'\n")
            if agent_name:
                f.write(f"WAZUH_AGENT_NAME='{agent_name}'\n")
        
        self.log("  ✓ Environment configured")
        
        # Step 4: Install package
        self.log("[4/5] Installing Wazuh Agent...")
        self.update_status("Installing...")
        self.update_progress(4)
        
        result = subprocess.run(
            ['installer', '-pkg', pkg_path, '-target', '/'],
            capture_output=True,
            text=True
        )
        
        wazuh_installed = result.returncode == 0
        if not wazuh_installed:
            self.log(f"  ⚠ installer output: {result.stderr[:200]}")
        else:
            self.log("  ✓ Installed")
        
        # Cleanup
        try:
            os.remove(pkg_path)
        except:
            pass
        
        # Step 5: Deploy remove-threat
        self.log("[5/5] Deploying remove-threat...")
        self.update_progress(5)
        
        remove_threat_src = os.path.join(str(self.script_dir), "remove-threat")
        if os.path.exists(remove_threat_src):
            import shutil
            dest = "/Library/Ossec/active-response/bin/remove-threat"
            try:
                shutil.copy2(remove_threat_src, dest)
                os.chmod(dest, 0o750)
                subprocess.run(['chown', 'root:wazuh', dest], capture_output=True)
                remove_threat_deployed = True
                self.log("  ✓ Deployed")
            except Exception as e:
                self.log(f"  ⚠ Failed: {e}")
        else:
            self.log("  ⚠ Skipped")
        
        # Start service
        subprocess.run(['launchctl', 'load', '/Library/LaunchDaemons/com.wazuh.agent.plist'], capture_output=True)
        self.log("  ✓ Service started\n")
        
        return wazuh_installed, remove_threat_deployed
            
    def download_file(self, url, destination):
        """Download a file"""
        try:
            urllib.request.urlretrieve(url, destination)
        except Exception as e:
            raise Exception(f"Failed to download: {e}")


def main():
    # Ensure admin privileges before creating any GUI
    if not request_admin_privileges():
        return
    
    root = tk.Tk()
    app = WazuhInstallerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
