import subprocess
import sys
import time
import datetime
import os
import json
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import csv

class EnhancedSystemAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced Windows System Information Analyzer - v2.0")
        self.root.geometry("1000x750")
        self.root.configure(bg='#f0f0f0')
        
        self.is_running = False
        self.output_data = {}
        self.report_data = []
        self.remote_mode = False
        self.target_computer = ""
        self.username = ""
        self.password = ""
        
        # Enhanced system commands with WiFi fix
        self.system_commands = {
            "System Information": "systeminfo",
            "IP Configuration": "ipconfig /all",
            "Network Connections": "netstat -an",
            "Active Processes": "tasklist",
            "Open Ports": "netstat -ano",
            "ARP Table": "arp -a",
            "Routing Table": "route print",
            "DNS Information": "nslookup google.com",
            "Windows Version": "ver",
            "Environment Variables": "set",
            "Hardware Info": "wmic computersystem get model,name,manufacturer,systemtype",
            "CPU Information": "wmic cpu get name,numberofcores,maxclockspeed",
            "Memory Information": "wmic memorychip get capacity,speed,manufacturer",
            "Disk Information": "wmic logicaldisk get size,freespace,caption",
            "Network Adapters": "wmic nic get name,macaddress,netconnectionstatus",
            "Installed Programs": "wmic product get name,version,vendor",
            "Services": "sc query",
            "User Accounts": "net user",
            "Firewall Status": "netsh advfirewall show allprofiles",
            "WiFi Profiles": "cmd /c \"netsh wlan show profiles 2>nul\""
        }
        
        self.setup_ui()
        
    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Enhanced Windows System Information Analyzer v2.0", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Mode selection
        mode_frame = ttk.LabelFrame(main_frame, text="Analysis Mode", padding="10")
        mode_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.analysis_mode = tk.StringVar(value="local")
        ttk.Radiobutton(mode_frame, text="Local System Analysis", variable=self.analysis_mode, 
                       value="local", command=self.toggle_mode).grid(row=0, column=0, padx=(0, 20))
        ttk.Radiobutton(mode_frame, text="Remote System Analysis", variable=self.analysis_mode, 
                       value="remote", command=self.toggle_mode).grid(row=0, column=1)
        
        # Remote system frame
        self.remote_frame = ttk.LabelFrame(main_frame, text="Remote System Details", padding="10")
        self.remote_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(self.remote_frame, text="Computer/IP:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.computer_entry = ttk.Entry(self.remote_frame, width=25)
        self.computer_entry.grid(row=0, column=1, padx=(0, 15))
        
        ttk.Label(self.remote_frame, text="Username:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.username_entry = ttk.Entry(self.remote_frame, width=20)
        self.username_entry.grid(row=0, column=3, padx=(0, 15))
        
        ttk.Label(self.remote_frame, text="Password:").grid(row=0, column=4, sticky=tk.W, padx=(0, 5))
        self.password_entry = ttk.Entry(self.remote_frame, width=20, show="*")
        self.password_entry.grid(row=0, column=5, padx=(0, 15))
        
        self.test_btn = ttk.Button(self.remote_frame, text="Test Connection", command=self.test_connection)
        self.test_btn.grid(row=0, column=6)
        
        self.remote_frame.grid_remove()  # Initially hidden
        
        # Control frame
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=3, column=0, columnspan=3, pady=(0, 10), sticky=(tk.W, tk.E))
        control_frame.rowconfigure(0, weight=0)
        control_frame.rowconfigure(1, weight=1)
        
        # Buttons frame
        button_frame = ttk.Frame(control_frame)
        button_frame.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E))
        
        self.start_button = ttk.Button(button_frame, text="Start Analysis", 
                                      command=self.start_analysis)
        self.start_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_button = ttk.Button(button_frame, text="Stop Analysis", 
                                     command=self.stop_analysis, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.clear_button = ttk.Button(button_frame, text="Clear Output", 
                                      command=self.clear_output)
        self.clear_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.export_button = ttk.Button(button_frame, text="Export Report", 
                                       command=self.export_report)
        self.export_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(button_frame, variable=self.progress_var, 
                                           maximum=len(self.system_commands))
        self.progress_bar.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(10, 0))
        
        # Notebook with tabs
        notebook = ttk.Notebook(control_frame)
        notebook.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        
        # Real-time output tab
        output_frame = ttk.Frame(notebook)
        notebook.add(output_frame, text="Real-time Output")
        
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, 
                                                    font=('Consolas', 9))
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Summary report tab
        summary_frame = ttk.Frame(notebook)
        notebook.add(summary_frame, text="Summary Report")
        
        self.summary_text = scrolledtext.ScrolledText(summary_frame, wrap=tk.WORD, 
                                                     font=('Arial', 10))
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready - Local Analysis Mode")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, 
                              relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
    def toggle_mode(self):
        if self.analysis_mode.get() == "remote":
            self.remote_frame.grid()
            self.status_var.set("Ready - Remote Analysis Mode")
            self.start_button.config(text="Start Remote Analysis")
        else:
            self.remote_frame.grid_remove()
            self.status_var.set("Ready - Local Analysis Mode")
            self.start_button.config(text="Start Analysis")
    
    def test_connection(self):
        computer = self.computer_entry.get().strip()
        if not computer:
            messagebox.showerror("Error", "Please enter a computer name or IP address")
            return
        
        self.update_status("Testing connection...")
        
        try:
            result = subprocess.run(
                f"ping -n 1 {computer}", 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=10, 
                encoding='utf-8', 
                errors='ignore'
            )
            
            if result.returncode == 0:
                self.update_status(f"Connection to {computer} successful")
                messagebox.showinfo("Success", f"Successfully connected to {computer}")
            else:
                self.update_status("Connection failed")
                messagebox.showerror("Error", f"Cannot reach {computer}")
        
        except Exception as e:
            self.update_status("Connection test failed")
            messagebox.showerror("Error", f"Connection test failed: {str(e)}")
    
    def log_output(self, message):
        def append_text():
            self.output_text.insert(tk.END, message + "\n")
            self.output_text.see(tk.END)
            self.root.update_idletasks()
        
        if threading.current_thread() == threading.main_thread():
            append_text()
        else:
            self.root.after_idle(append_text)
    
    def update_status(self, status):
        def update():
            self.status_var.set(status)
        
        if threading.current_thread() == threading.main_thread():
            update()
        else:
            self.root.after_idle(update)
    
    def update_progress(self, value):
        def update():
            self.progress_var.set(value)
        
        if threading.current_thread() == threading.main_thread():
            update()
        else:
            self.root.after_idle(update)
    
    def execute_command_realtime(self, command_name, command):
        self.log_output(f"\n{'='*60}")
        
        if self.analysis_mode.get() == "remote":
            self.log_output(f"Executing on {self.target_computer}: {command_name}")
            final_command = self.build_remote_command(command)
        else:
            self.log_output(f"Executing locally: {command_name}")
            final_command = command
            
        self.log_output(f"Command: {command}")
        self.log_output(f"{'='*60}")
        
        try:
            # Special handling for WiFi commands with Unicode support
            if 'wlan' in command or 'wifi' in command_name.lower():
                process = subprocess.Popen(
                    final_command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding='utf-8',
                    errors='ignore',
                    universal_newlines=True,
                    bufsize=1
                )
            else:
                process = subprocess.Popen(
                    final_command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding='utf-8',
                    errors='ignore',
                    universal_newlines=True,
                    bufsize=1
                )
            
            output_lines = []
            
            while True:
                if not self.is_running:
                    process.terminate()
                    break
                    
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                    
                if line:
                    line = line.rstrip()
                    # Safe output with Unicode handling
                    try:
                        self.log_output(line)
                    except (UnicodeEncodeError, UnicodeDecodeError):
                        safe_line = line.encode('ascii', errors='ignore').decode('ascii')
                        self.log_output(safe_line)
                    output_lines.append(line)
            
            # Get any remaining output
            remaining_output, _ = process.communicate()
            if remaining_output:
                for line in remaining_output.split('\n'):
                    if line.strip():
                        try:
                            self.log_output(line)
                        except (UnicodeEncodeError, UnicodeDecodeError):
                            safe_line = line.encode('ascii', errors='ignore').decode('ascii')
                            self.log_output(safe_line)
                        output_lines.append(line)
            
            self.output_data[command_name] = {
                'command': command,
                'final_command': final_command,
                'target': self.target_computer if self.analysis_mode.get() == "remote" else "localhost",
                'output': output_lines,
                'timestamp': datetime.datetime.now().isoformat(),
                'return_code': process.returncode
            }
            
            self.log_output(f"Command completed with return code: {process.returncode}")
            return True
            
        except Exception as e:
            error_msg = f"Error executing {command_name}: {str(e)}"
            self.log_output(error_msg)
            self.output_data[command_name] = {
                'command': command,
                'final_command': final_command,
                'target': self.target_computer if self.analysis_mode.get() == "remote" else "localhost",
                'output': [error_msg],
                'timestamp': datetime.datetime.now().isoformat(),
                'return_code': -1,
                'error': str(e)
            }
            return False
    
    def build_remote_command(self, base_command):
        if not self.target_computer or not self.username or not self.password:
            return base_command
        
        if base_command.startswith("wmic"):
            remote_cmd = f'wmic /node:"{self.target_computer}" /user:"{self.username}" /password:"{self.password}" {base_command[5:]}'
        elif base_command.startswith("cmd /c"):
            # Special handling for cmd /c commands like WiFi
            remote_cmd = f'wmic /node:"{self.target_computer}" /user:"{self.username}" /password:"{self.password}" process call create "{base_command}"'
        elif base_command in ["systeminfo", "ipconfig /all", "netstat -an", "netstat -ano", "tasklist", "arp -a", "route print", "ver", "sc query", "net user"]:
            remote_cmd = f'wmic /node:"{self.target_computer}" /user:"{self.username}" /password:"{self.password}" process call create "cmd /c {base_command}"'
        elif base_command.startswith("netsh"):
            remote_cmd = f'wmic /node:"{self.target_computer}" /user:"{self.username}" /password:"{self.password}" process call create "cmd /c {base_command}"'
        else:
            remote_cmd = f'wmic /node:"{self.target_computer}" /user:"{self.username}" /password:"{self.password}" process call create "cmd /c {base_command}"'
        
        return remote_cmd
    
    def analysis_thread(self):
        try:
            if self.analysis_mode.get() == "remote":
                self.target_computer = self.computer_entry.get().strip()
                self.username = self.username_entry.get().strip()
                self.password = self.password_entry.get().strip()
                
                if not all([self.target_computer, self.username, self.password]):
                    messagebox.showerror("Error", "Please fill in all remote connection fields")
                    return
                
                self.update_status(f"Starting remote analysis of {self.target_computer}...")
                self.log_output(f"Remote System Analysis Started at {datetime.datetime.now()}")
                self.log_output(f"Target: {self.target_computer}")
                self.log_output(f"User: {self.username}")
            else:
                self.update_status("Starting local system analysis...")
                self.log_output(f"Local System Analysis Started at {datetime.datetime.now()}")
                self.log_output(f"Computer: {os.environ.get('COMPUTERNAME', 'Unknown')}")
                self.log_output(f"User: {os.environ.get('USERNAME', 'Unknown')}")
            
            self.log_output(f"Total commands to execute: {len(self.system_commands)}")
            
            completed = 0
            successful = 0
            failed = 0
            
            for command_name, command in self.system_commands.items():
                if not self.is_running:
                    break
                
                self.update_status(f"Executing: {command_name}")
                success = self.execute_command_realtime(command_name, command)
                
                if success:
                    successful += 1
                else:
                    failed += 1
                
                completed += 1
                self.update_progress(completed)
                
                if self.is_running:
                    time.sleep(0.5)  # Small delay between commands
            
            if self.is_running:
                self.generate_summary_report()
                self.update_status(f"Analysis completed - {successful}/{len(self.system_commands)} successful")
                self.log_output(f"\nSystem Analysis Completed at {datetime.datetime.now()}")
                self.log_output(f"Final Results: {successful} successful, {failed} failed")
                messagebox.showinfo("Complete", f"System analysis completed!\n\nResults: {successful}/{len(self.system_commands)} commands successful")
            else:
                self.update_status("Analysis stopped by user")
                self.log_output("\nAnalysis stopped by user")
            
        except Exception as e:
            error_msg = f"Analysis failed: {str(e)}"
            self.update_status(error_msg)
            self.log_output(error_msg)
            messagebox.showerror("Error", error_msg)
        finally:
            self.is_running = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
    
    def generate_summary_report(self):
        self.summary_text.delete(1.0, tk.END)
        
        report = []
        if self.analysis_mode.get() == "remote":
            report.append("REMOTE WINDOWS SYSTEM ANALYSIS SUMMARY REPORT")
        else:
            report.append("LOCAL WINDOWS SYSTEM ANALYSIS SUMMARY REPORT")
        
        report.append("=" * 60)
        report.append(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Analyzer Version: Enhanced System Analyzer v2.0")
        
        if self.analysis_mode.get() == "remote":
            report.append(f"Target Computer: {self.target_computer}")
            report.append(f"Analyzed from: {os.environ.get('COMPUTERNAME', 'Unknown')}")
        else:
            report.append(f"Computer: {os.environ.get('COMPUTERNAME', 'Unknown')}")
        
        report.append(f"User: {os.environ.get('USERNAME', 'Unknown')}")
        report.append("")
        
        # Extract and display key system information
        key_info = self.extract_key_information()
        
        if key_info:
            report.append("KEY SYSTEM INFORMATION:")
            report.append("-" * 30)
            for category, info in key_info.items():
                report.append(f"\n{category}:")
                for key, value in info.items():
                    report.append(f"  {key}: {value}")
        
        report.append("\n\nCOMMAND EXECUTION SUMMARY:")
        report.append("-" * 30)
        successful = 0
        failed = 0
        
        for cmd_name, cmd_data in self.output_data.items():
            status = "SUCCESS" if cmd_data.get('return_code', -1) == 0 else "FAILED"
            if status == "SUCCESS":
                successful += 1
            else:
                failed += 1
            report.append(f"{cmd_name}: {status}")
        
        report.append(f"\nEXECUTION STATISTICS:")
        report.append(f"Total Commands: {len(self.output_data)}")
        report.append(f"Successful: {successful}")
        report.append(f"Failed: {failed}")
        report.append(f"Success Rate: {(successful/len(self.output_data)*100):.1f}%" if self.output_data else "0.0%")
        
        report_text = "\n".join(report)
        self.summary_text.insert(tk.END, report_text)
        
        self.report_data = report
    
    def extract_key_information(self):
        key_info = {}
        
        # Extract system information
        if "System Information" in self.output_data:
            sys_info = {}
            for line in self.output_data["System Information"]["output"]:
                if ":" in line and not line.startswith(" "):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip()
                        if key in ["Host Name", "OS Name", "OS Version", "System Type", "Total Physical Memory"]:
                            sys_info[key] = value
            if sys_info:
                key_info["System"] = sys_info
        
        # Extract network information
        if "IP Configuration" in self.output_data:
            network_info = {}
            for line in self.output_data["IP Configuration"]["output"]:
                if any(keyword in line for keyword in ["IPv4 Address", "Physical Address", "Default Gateway"]):
                    if ":" in line:
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            key = parts[0].strip()
                            value = parts[1].strip()
                            if value and value not in ["", "(Preferred)"]:
                                network_info[key] = value
            if network_info:
                key_info["Network"] = network_info
        
        return key_info
    
    def start_analysis(self):
        if not self.is_running:
            self.is_running = True
            self.output_data = {}
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.update_progress(0)
            
            analysis_thread = threading.Thread(target=self.analysis_thread)
            analysis_thread.daemon = True
            analysis_thread.start()
    
    def stop_analysis(self):
        self.is_running = False
        self.update_status("Stopping analysis...")
    
    def clear_output(self):
        self.output_text.delete(1.0, tk.END)
        self.summary_text.delete(1.0, tk.END)
        self.output_data = {}
        self.update_progress(0)
        if self.analysis_mode.get() == "remote":
            self.update_status("Ready - Remote Analysis Mode")
        else:
            self.update_status("Ready - Local Analysis Mode")
    
    def export_report(self):
        if not self.output_data:
            messagebox.showwarning("No Data", "No analysis data to export. Please run an analysis first.")
            return
        
        # Create filename with timestamp
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if self.analysis_mode.get() == "remote":
            base_name = f"analysis_{self.target_computer}_{timestamp}"
        else:
            base_name = f"analysis_local_{timestamp}"
        
        try:
            # Export both JSON and TXT formats automatically
            json_filename = f"{base_name}.json"
            txt_filename = f"{base_name}.txt"
            csv_filename = f"{base_name}.csv"
            
            self.export_json(json_filename)
            self.export_txt(txt_filename)
            self.export_csv(csv_filename)
            
            messagebox.showinfo("Export Complete", 
                f"Reports exported successfully:\n\n"
                f"• JSON: {json_filename}\n"
                f"• TXT: {txt_filename}\n"
                f"• CSV: {csv_filename}\n\n"
                f"Files saved in: {os.getcwd()}")
                
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export: {str(e)}")
    
    def export_json(self, filename):
        export_data = {
            'analysis_info': {
                'timestamp': datetime.datetime.now().isoformat(),
                'version': '2.0',
                'mode': self.analysis_mode.get(),
                'target': self.target_computer if self.analysis_mode.get() == "remote" else os.environ.get('COMPUTERNAME', 'Unknown'),
                'analyzer': os.environ.get('COMPUTERNAME', 'Unknown'),
                'user': os.environ.get('USERNAME', 'Unknown'),
                'total_commands': len(self.output_data),
                'successful_commands': sum(1 for cmd in self.output_data.values() if cmd.get('return_code') == 0),
                'failed_commands': sum(1 for cmd in self.output_data.values() if cmd.get('return_code') != 0)
            },
            'key_information': self.extract_key_information(),
            'commands': self.output_data
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
    
    def export_csv(self, filename):
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Command Name', 'Target', 'Command', 'Timestamp', 'Return Code', 'Output Lines', 'Status'])
            
            for cmd_name, cmd_data in self.output_data.items():
                status = 'Success' if cmd_data.get('return_code', -1) == 0 else 'Failed'
                output_count = len(cmd_data.get('output', []))
                
                writer.writerow([
                    cmd_name,
                    cmd_data.get('target', ''),
                    cmd_data.get('command', ''),
                    cmd_data.get('timestamp', ''),
                    cmd_data.get('return_code', -1),
                    output_count,
                    status
                ])
    
    def export_txt(self, filename):
        with open(filename, 'w', encoding='utf-8') as f:
            if self.report_data:
                f.write("\n".join(self.report_data))
                f.write("\n\n" + "="*80 + "\n")
                f.write("DETAILED COMMAND OUTPUTS\n")
                f.write("="*80 + "\n\n")
            
            for cmd_name, cmd_data in self.output_data.items():
                f.write(f"Command: {cmd_name}\n")
                f.write(f"Target: {cmd_data.get('target', '')}\n")
                f.write(f"Executed: {cmd_data.get('command', '')}\n")
                f.write(f"Final Command: {cmd_data.get('final_command', '')}\n")
                f.write(f"Timestamp: {cmd_data.get('timestamp', '')}\n")
                f.write(f"Return Code: {cmd_data.get('return_code', -1)}\n")
                f.write("-" * 60 + "\n")
                
                for line in cmd_data.get('output', []):
                    f.write(f"{line}\n")
                
                f.write("\n" + "="*80 + "\n\n")

def main():
    if os.name != 'nt':
        print("This application is designed for Windows systems only.")
        sys.exit(1)
    
    root = tk.Tk()
    app = EnhancedSystemAnalyzer(root)
    
    # Center the window
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (1000 // 2)
    y = (root.winfo_screenheight() // 2) - (750 // 2)
    root.geometry(f"1000x750+{x}+{y}")
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
        sys.exit(0)

if __name__ == "__main__":
    main()