import subprocess
import sys
import time
import datetime
import os
import json
import argparse

class EnhancedSystemCLI:
    def __init__(self):
        self.output_data = {}
        self.is_remote = False
        self.target_computer = ""
        self.username = ""
        self.password = ""
        
        self.system_commands = {
            "system_info": ("System Information", "systeminfo"),
            "ip_config": ("IP Configuration", "ipconfig /all"),
            "network_connections": ("Network Connections", "netstat -an"),
            "active_processes": ("Active Processes", "tasklist"),
            "open_ports": ("Open Ports", "netstat -ano"),
            "arp_table": ("ARP Table", "arp -a"),
            "routing_table": ("Routing Table", "route print"),
            "dns_info": ("DNS Information", "nslookup google.com"),
            "windows_version": ("Windows Version", "ver"),
            "environment_vars": ("Environment Variables", "set"),
            "hardware_info": ("Hardware Info", "wmic computersystem get model,name,manufacturer,systemtype"),
            "cpu_info": ("CPU Information", "wmic cpu get name,numberofcores,maxclockspeed"),
            "memory_info": ("Memory Information", "wmic memorychip get capacity,speed,manufacturer"),
            "disk_info": ("Disk Information", "wmic logicaldisk get size,freespace,caption"),
            "network_adapters": ("Network Adapters", "wmic nic get name,macaddress,netconnectionstatus"),
            "installed_programs": ("Installed Programs", "wmic product get name,version,vendor"),
            "services": ("Services", "sc query"),
            "user_accounts": ("User Accounts", "net user"),
            "firewall_status": ("Firewall Status", "netsh advfirewall show allprofiles"),
            "wifi_profiles": ("WiFi Profiles", "cmd /c \"netsh wlan show profiles 2>nul\"")
        }
    
    def print_banner(self):
        banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                Enhanced Windows System Information Analyzer          ║
║                        Command Line Interface v2.0                  ║
║                     Local & Remote Analysis Tool                     ║
║                           Unicode Support Enabled                    ║
╚══════════════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def test_connection(self, target):
        print(f"Testing connection to {target}...")
        try:
            result = subprocess.run(
                f"ping -n 1 {target}", 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=10,
                encoding='utf-8',
                errors='ignore'
            )
            if result.returncode == 0:
                print(f"✓ Connection to {target} successful")
                return True
            else:
                print(f"✗ Cannot reach {target}")
                return False
        except Exception as e:
            print(f"✗ Connection test failed: {e}")
            return False
    
    def build_remote_command(self, base_command):
        if not self.target_computer or not self.username or not self.password:
            return base_command
        
        if base_command.startswith("wmic"):
            remote_cmd = f'wmic /node:"{self.target_computer}" /user:"{self.username}" /password:"{self.password}" {base_command[5:]}'
        else:
            remote_cmd = f'wmic /node:"{self.target_computer}" /user:"{self.username}" /password:"{self.password}" process call create "cmd /c {base_command}"'
        
        return remote_cmd
    
    def execute_command(self, command_name, command, verbose=True):
        if verbose:
            print(f"\n{'='*70}")
            if self.is_remote:
                print(f"Executing on {self.target_computer}: {command_name}")
            else:
                print(f"Executing locally: {command_name}")
            print(f"Command: {command}")
            print(f"{'='*70}")
        
        try:
            if self.is_remote:
                final_command = self.build_remote_command(command)
            else:
                final_command = command
            
            # Special handling for WiFi commands with increased timeout and Unicode support
            if 'wlan' in command or 'wifi' in command.lower():
                timeout_val = 60
                try:
                    result = subprocess.run(
                        final_command, 
                        shell=True, 
                        capture_output=True, 
                        text=True, 
                        timeout=timeout_val,
                        encoding='utf-8',
                        errors='ignore',
                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
                    )
                except AttributeError:
                    # Fallback for systems without CREATE_NO_WINDOW
                    result = subprocess.run(
                        final_command, 
                        shell=True, 
                        capture_output=True, 
                        text=True, 
                        timeout=timeout_val,
                        encoding='utf-8',
                        errors='ignore'
                    )
            else:
                # Standard commands with Unicode support
                result = subprocess.run(
                    final_command, 
                    shell=True, 
                    capture_output=True, 
                    text=True, 
                    timeout=30,
                    encoding='utf-8',
                    errors='ignore'
                )
            
            output_lines = result.stdout.split('\n') if result.stdout else []
            self.output_data[command_name] = {
                'command': command,
                'final_command': final_command,
                'target': self.target_computer if self.is_remote else "localhost",
                'output': output_lines,
                'timestamp': datetime.datetime.now().isoformat(),
                'return_code': result.returncode
            }
            
            if verbose:
                for line in output_lines:
                    if line.strip():
                        # Safe printing with Unicode handling
                        try:
                            print(line)
                        except UnicodeEncodeError:
                            print(line.encode('ascii', errors='ignore').decode('ascii'))
                print(f"\nCommand completed with return code: {result.returncode}")
            
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            error_msg = f"Command '{command}' timed out after {timeout_val if 'wlan' in command else 30} seconds"
            print(f"ERROR: {error_msg}")
            self.output_data[command_name] = {
                'command': command,
                'final_command': final_command,
                'target': self.target_computer if self.is_remote else "localhost",
                'output': [error_msg],
                'timestamp': datetime.datetime.now().isoformat(),
                'return_code': -1,
                'timeout': True
            }
            return False
            
        except Exception as e:
            error_msg = f"Error executing '{command}': {str(e)}"
            print(f"ERROR: {error_msg}")
            self.output_data[command_name] = {
                'command': command,
                'final_command': final_command,
                'target': self.target_computer if self.is_remote else "localhost",
                'output': [error_msg],
                'timestamp': datetime.datetime.now().isoformat(),
                'return_code': -1,
                'error': str(e)
            }
            return False
    
    def run_analysis(self, selected_commands=None, verbose=True):
        if verbose:
            self.print_banner()
            if self.is_remote:
                print(f"Starting REMOTE system analysis")
                print(f"Target Computer: {self.target_computer}")
                print(f"Username: {self.username}")
            else:
                print(f"Starting LOCAL system analysis")
                print(f"Computer: {os.environ.get('COMPUTERNAME', 'Unknown')}")
                print(f"User: {os.environ.get('USERNAME', 'Unknown')}")
            print(f"Started at: {datetime.datetime.now()}")
        
        commands_to_run = self.system_commands
        if selected_commands:
            commands_to_run = {k: v for k, v in self.system_commands.items() if k in selected_commands}
        
        if verbose:
            print(f"Total commands to execute: {len(commands_to_run)}")
        
        successful = failed = 0
        for i, (cmd_key, (cmd_name, cmd_command)) in enumerate(commands_to_run.items(), 1):
            if verbose:
                print(f"\n[{i}/{len(commands_to_run)}] Processing: {cmd_name}")
            
            if self.execute_command(cmd_name, cmd_command, verbose):
                successful += 1
                if verbose:
                    print(f"✓ {cmd_name}: SUCCESS")
            else:
                failed += 1
                if verbose:
                    print(f"✗ {cmd_name}: FAILED")
            
            # Small delay between commands
            time.sleep(0.2)
        
        if verbose:
            print(f"\n{'='*70}")
            print("LOCAL ANALYSIS COMPLETE" if not self.is_remote else "REMOTE ANALYSIS COMPLETE")
            print(f"{'='*70}")
            print(f"Total commands executed: {len(commands_to_run)}")
            print(f"✓ Successful: {successful}")
            print(f"✗ Failed: {failed}")
            print(f"Success Rate: {(successful/len(commands_to_run)*100):.1f}%")
            print(f"Completed at: {datetime.datetime.now()}")
        
        return successful, failed
    
    def generate_summary(self):
        summary = []
        summary.append("ENHANCED WINDOWS SYSTEM ANALYSIS SUMMARY" if not self.is_remote else "ENHANCED REMOTE WINDOWS SYSTEM ANALYSIS SUMMARY")
        summary.append("=" * 60)
        summary.append(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        summary.append(f"Analysis Tool: Enhanced System Analyzer CLI v2.0")
        
        if self.is_remote:
            summary.append(f"Target Computer: {self.target_computer}")
            summary.append(f"Analyzed from: {os.environ.get('COMPUTERNAME', 'Unknown')}")
        else:
            summary.append(f"Computer: {os.environ.get('COMPUTERNAME', 'Unknown')}")
        
        summary.append(f"User: {os.environ.get('USERNAME', 'Unknown')}")
        summary.append("")
        
        # Extract key system information
        key_info = self.extract_key_information()
        if key_info:
            summary.append("KEY SYSTEM INFORMATION:")
            summary.append("-" * 40)
            for category, info in key_info.items():
                summary.append(f"\n{category}:")
                for key, value in info.items():
                    summary.append(f"  {key}: {value}")
            summary.append("")
        
        summary.append("COMMAND EXECUTION SUMMARY:")
        summary.append("-" * 40)
        successful = failed = 0
        
        for cmd_name, cmd_data in self.output_data.items():
            status = "SUCCESS" if cmd_data.get('return_code', -1) == 0 else "FAILED"
            if status == "SUCCESS":
                successful += 1
            else:
                failed += 1
            summary.append(f"{cmd_name}: {status}")
        
        summary.append(f"\nEXECUTION STATISTICS:")
        summary.append(f"Total Commands: {len(self.output_data)}")
        summary.append(f"Successful: {successful}")
        summary.append(f"Failed: {failed}")
        summary.append(f"Success Rate: {(successful/len(self.output_data)*100):.1f}%" if self.output_data else "0.0%")
        
        return "\n".join(summary)
    
    def extract_key_information(self):
        """Extract key information from command outputs"""
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
                            if value and value != "N/A":
                                network_info[key] = value
            if network_info:
                key_info["Network"] = network_info
        
        return key_info
    
    def export_json(self, filename):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if not filename.endswith('.json'):
            filename = f"{filename}_{timestamp}.json"
        
        export_data = {
            'analysis_info': {
                'timestamp': datetime.datetime.now().isoformat(),
                'version': '2.0',
                'mode': 'remote' if self.is_remote else 'local',
                'target': self.target_computer if self.is_remote else os.environ.get('COMPUTERNAME', 'Unknown'),
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
        print(f"✓ Results exported to: {filename}")
        print(f"  File size: {os.path.getsize(filename)} bytes")
    
    def export_text(self, filename):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if not filename.endswith('.txt'):
            filename = f"{filename}_{timestamp}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(self.generate_summary())
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
        
        print(f"✓ Report exported to: {filename}")
        print(f"  File size: {os.path.getsize(filename)} bytes")

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced Windows System Information Analyzer CLI v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python %(prog)s --summary                    # Quick local analysis with summary
  python %(prog)s --list                       # List all available commands
  python %(prog)s --commands system_info       # Run specific command
  python %(prog)s --output report.json         # Export to JSON file
  python %(prog)s --remote -c 192.168.1.100    # Remote analysis
  python %(prog)s --quiet --output report      # Silent mode with export
        """
    )
    
    # Analysis mode options
    parser.add_argument("--remote", "-r", action="store_true", 
                       help="Enable remote analysis mode")
    parser.add_argument("--computer", "-c", type=str, 
                       help="Remote computer name or IP address")
    parser.add_argument("--username", "-u", type=str, 
                       help="Username for remote connection")
    parser.add_argument("--password", "-p", type=str, 
                       help="Password for remote connection")
    
    # Command selection options
    parser.add_argument("--commands", nargs="+", 
                       help="Specific commands to run (use --list to see options)")
    parser.add_argument("--list", "-l", action="store_true", 
                       help="List all available commands and exit")
    
    # Output options
    parser.add_argument("--output", "-o", type=str, 
                       help="Output file (.json or .txt extension)")
    parser.add_argument("--quiet", "-q", action="store_true", 
                       help="Run in quiet mode (minimal output)")
    parser.add_argument("--summary", "-s", action="store_true", 
                       help="Show summary report only")
    parser.add_argument("--test", "-t", action="store_true", 
                       help="Test remote connection only (requires --remote)")
    
    args = parser.parse_args()
    
    # System compatibility check
    if os.name != 'nt':
        print("ERROR: This application is designed for Windows systems only.")
        print("Current OS detected:", os.name)
        sys.exit(1)
    
    analyzer = EnhancedSystemCLI()
    
    # Handle list command
    if args.list:
        print("Enhanced Windows System Information Analyzer CLI v2.0")
        print("Available commands:")
        print("-" * 60)
        for key, (name, command) in analyzer.system_commands.items():
            print(f"{key:20} - {name}")
            print(f"{'':20}   Command: {command}")
        print("-" * 60)
        print(f"Total commands available: {len(analyzer.system_commands)}")
        sys.exit(0)
    
    # Handle remote mode setup
    if args.remote:
        if not args.computer:
            print("ERROR: --computer is required for remote analysis")
            print("Example: --remote --computer 192.168.1.100 --username admin")
            sys.exit(1)
        
        analyzer.is_remote = True
        analyzer.target_computer = args.computer
        analyzer.username = args.username or input("Username: ")
        
        if not args.password:
            import getpass
            analyzer.password = getpass.getpass("Password: ")
        else:
            analyzer.password = args.password
        
        # Test connection if requested
        if args.test:
            print("Testing remote connection...")
            if analyzer.test_connection(analyzer.target_computer):
                print("✓ Connection test successful!")
                print(f"Ready to analyze: {analyzer.target_computer}")
            else:
                print("✗ Connection test failed!")
            sys.exit(0)
        
        # Verify connection before analysis
        if not analyzer.test_connection(analyzer.target_computer):
            print("ERROR: Cannot connect to remote computer. Aborting analysis.")
            sys.exit(1)
    
    # Run analysis
    try:
        verbose = not args.quiet
        successful, failed = analyzer.run_analysis(args.commands, verbose)
        
        # Show summary if requested or in quiet mode
        if args.summary or args.quiet:
            print("\n" + analyzer.generate_summary())
        
        # Export results if output file specified
        if args.output:
            if args.output.lower().endswith('.json'):
                analyzer.export_json(args.output)
            else:
                if not args.output.lower().endswith('.txt'):
                    args.output += '.txt'
                analyzer.export_text(args.output)
        
        # Exit with appropriate code
        sys.exit(0 if failed == 0 else 1)
        
    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user")
        print("Partial results may be available")
        sys.exit(130)  # Standard exit code for Ctrl+C
    except Exception as e:
        print(f"\nFATAL ERROR: {str(e)}")
        print("Please check your system configuration and try again")
        sys.exit(1)

if __name__ == "__main__":
    main()