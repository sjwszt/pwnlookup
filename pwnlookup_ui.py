#!/usr/bin/env python3
"""
PwnLookup Interactive UI
A pwncat-like terminal UI using Prompt Toolkit for interaction and Rich for styling
"""

import os
import sys
import time
import threading
import subprocess
import signal
import shlex
from typing import List, Dict, Any, Optional, Tuple, Union, Callable

import rich
from rich.console import Console
from rich.theme import Theme
from rich.text import Text
from rich.syntax import Syntax
from rich.panel import Panel
from rich.logging import RichHandler
from rich import box

from prompt_toolkit import PromptSession, HTML
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter, NestedCompleter
from prompt_toolkit.styles import Style
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.layout import Layout, HSplit, VSplit, Window, FormattedTextControl
from prompt_toolkit.layout.containers import FloatContainer, Float
from prompt_toolkit.layout.dimension import D
from prompt_toolkit.application import Application
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.filters import Condition
from prompt_toolkit.widgets import TextArea

import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger("pwnlookup")

# Rich theme
rich_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "command": "bold blue",
    "prompt": "bold magenta",
})

# Rich console
console = Console(theme=rich_theme)

class PwnLookupUI:
    """Interactive UI for PwnLookup using Prompt Toolkit"""
    
    def __init__(self):
        """Initialize the UI"""
        self.running = True
        self.process = None
        self.gdb_process = None
        self.target_binary = None
        self.connected = False
        self.show_help_panel = False
        self.hex_view = False  # Toggle for hex view
        
        # Command history
        self.history = InMemoryHistory()
        
        # Command completions
        self.commands = {
            "connect": {
                "help": "Connect to a binary",
                "usage": "connect <binary> [args]",
                "completer": None  # Will be set to file completer
            },
            "disconnect": {
                "help": "Disconnect from the current target",
                "usage": "disconnect",
                "completer": None
            },
            "gdb": {
                "help": "Start GDB with the current target",
                "usage": "gdb [args]",
                "completer": None
            },
            "checksec": {
                "help": "Check security features of a binary",
                "usage": "checksec [binary]",
                "completer": None
            },
            "info": {
                "help": "Show information about a topic",
                "usage": "info <topic>",
                "completer": WordCompleter(["binary", "process", "gdb", "commands"])
            },
            "clear": {
                "help": "Clear the output panel",
                "usage": "clear",
                "completer": None
            },
            "shell": {
                "help": "Run a shell command",
                "usage": "shell <command>",
                "completer": None
            },
            "hexdump": {
                "help": "View memory in hex format",
                "usage": "hexdump <address> [length]",
                "completer": None
            },
            "memory": {
                "help": "View or modify process memory",
                "usage": "memory [read|write] <address> [value]",
                "completer": WordCompleter(["read", "write"])
            },
            "toggle": {
                "help": "Toggle UI features",
                "usage": "toggle [hex|help]",
                "completer": WordCompleter(["hex", "help"])
            },
            "help": {
                "help": "Show help information",
                "usage": "help [command]",
                "completer": WordCompleter(list(c for c in locals()))
            },
            "quit": {
                "help": "Exit PwnLookup",
                "usage": "quit",
                "completer": None
            },
            "exit": {
                "help": "Exit PwnLookup",
                "usage": "exit",
                "completer": None
            }
        }
        
        # Create nested completer
        self.completer = self._create_completer()
        
        # Key bindings
        self.bindings = self._create_key_bindings()
        
        # Output buffer
        self.output_buffer = []
        self.max_output_lines = 1000
        
        # Status information
        self.status = "Ready"
        self.status_info = {
            "Status": self.status,
            "Target": self.target_binary or "None",
            "Connected": "No",
            "GDB": "Not running"
        }
        
        # Create prompt session
        self.session = PromptSession(
            history=self.history,
            auto_suggest=AutoSuggestFromHistory(),
            completer=self.completer,
            key_bindings=self.bindings,
            style=Style.from_dict({
                'prompt': 'ansired bold',
                'completion-menu.completion': 'bg:#008888 #ffffff',
                'completion-menu.completion.current': 'bg:#00aaaa #000000',
                'scrollbar.background': 'bg:#88aaaa',
                'scrollbar.button': 'bg:#222222',
            }),
            enable_history_search=True,
            mouse_support=True,
            complete_while_typing=True
        )
        
        # Register signal handlers
        signal.signal(signal.SIGINT, self._handle_sigint)
    
    def _create_completer(self):
        """Create a nested completer for commands"""
        completions = {}
        for cmd, info in self.commands.items():
            if info["completer"]:
                completions[cmd] = info["completer"]
            else:
                completions[cmd] = None
        return NestedCompleter.from_nested_dict(completions)
    
    def _create_key_bindings(self):
        """Create key bindings for the UI"""
        bindings = KeyBindings()
        
        @bindings.add('c-c')
        def _(event):
            """Handle Ctrl+C"""
            if self.process:
                self._log("Received Ctrl+C, sending to process...")
                try:
                    self.process.send_signal(signal.SIGINT)
                except:
                    self._disconnect_target()
            else:
                self.running = False
                event.app.exit()
        
        @bindings.add('c-d')
        def _(event):
            """Handle Ctrl+D (EOF)"""
            if event.current_buffer.text:
                # If there's text, delete the character under the cursor
                event.current_buffer.delete()
            else:
                # If the buffer is empty, exit
                self.running = False
                event.app.exit()
        
        @bindings.add('f1')
        def _(event):
            """Toggle help panel"""
            self.show_help_panel = not self.show_help_panel
        
        @bindings.add('f2')
        def _(event):
            """Toggle hex view"""
            self.hex_view = not self.hex_view
            self._log(f"Hex view {'enabled' if self.hex_view else 'disabled'}", "info")
        
        return bindings
    
    def _log(self, message: str, level: str = "info") -> None:
        """Log a message with the specified level"""
        timestamp = time.strftime("[%H:%M:%S]")
        formatted_msg = f"{timestamp} {message}"
        
        # Add to output buffer
        self.output_buffer.append((level, formatted_msg))
        
        # Trim buffer if needed
        if len(self.output_buffer) > self.max_output_lines:
            self.output_buffer = self.output_buffer[-self.max_output_lines:]
        
        # Log to console
        if level == "info":
            logger.info(message)
        elif level == "warning":
            logger.warning(message)
        elif level == "error":
            logger.error(message)
        elif level == "success":
            logger.info(message)  # No success level in logging
    
    def _update_status(self, key: str, value: str) -> None:
        """Update a status value"""
        self.status_info[key] = value
    
    def _format_output(self) -> str:
        """Format the output buffer for display"""
        output_lines = []
        for level, msg in self.output_buffer:
            if level == "info":
                output_lines.append(f"[cyan]{msg}[/]")
            elif level == "warning":
                output_lines.append(f"[yellow]{msg}[/]")
            elif level == "error":
                output_lines.append(f"[bold red]{msg}[/]")
            elif level == "success":
                output_lines.append(f"[bold green]{msg}[/]")
            elif level == "command":
                output_lines.append(f"[bold blue]{msg}[/]")
            else:
                output_lines.append(msg)
        
        return "\n".join(output_lines)
    
    def _format_status(self) -> str:
        """Format the status information for display"""
        status_lines = []
        for key, value in self.status_info.items():
            status_lines.append(f"[cyan]{key}:[/] [green]{value}[/]")
        
        return "\n".join(status_lines)
    
    def _format_help(self) -> str:
        """Format the help information for display"""
        help_lines = ["[bold]Available Commands:[/]"]
        for cmd, info in self.commands.items():
            help_lines.append(f"[cyan]{cmd}[/]: {info['help']}")
            help_lines.append(f"  Usage: [green]{info['usage']}[/]")
        
        help_lines.append("\n[bold]Keyboard Shortcuts:[/]")
        help_lines.append("[cyan]F1[/]: Toggle help panel")
        help_lines.append("[cyan]F2[/]: Toggle hex view")
        help_lines.append("[cyan]Ctrl+C[/]: Interrupt process or exit")
        help_lines.append("[cyan]Ctrl+D[/]: Exit")
        help_lines.append("\n[bold]Special Input:[/]")
        help_lines.append("[cyan]!command[/]: Send 'command' to the process")
        
        return "\n".join(help_lines)
    
    def _handle_sigint(self, sig, frame) -> None:
        """Handle SIGINT (Ctrl+C)"""
        if self.process:
            self._log("Received SIGINT, terminating process...", "warning")
            self.process.terminate()
            self.process = None
            self.connected = False
            self._update_status("Connected", "No")
        elif self.gdb_process:
            self._log("Received SIGINT, terminating GDB...", "warning")
            self.gdb_process.terminate()
            self.gdb_process = None
            self._update_status("GDB", "Not running")
        else:
            self.running = False
    
    def _process_command(self, command: str) -> None:
        """Process a user command"""
        if not command.strip():
            return
            
        self._log(f"$ {command}", "command")
        
        # Split command and arguments
        parts = shlex.split(command)
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        # Process commands
        if cmd in ["quit", "exit"]:
            self.running = False
            self._log("Exiting PwnLookup...", "info")
            
        elif cmd == "help":
            self._show_help(args[0] if args else None)
            
        elif cmd == "connect":
            self._connect_target(args)
            
        elif cmd == "disconnect":
            self._disconnect_target()
            
        elif cmd == "gdb":
            self._start_gdb(args)
            
        elif cmd == "checksec":
            self._check_security(args)
            
        elif cmd == "info":
            self._show_info(args)
            
        elif cmd == "clear":
            self.output_buffer = []
            self._log("Output cleared", "info")
            
        elif cmd == "shell":
            self._run_shell_command(args)
            
        elif cmd == "hexdump":
            self._hexdump_memory(args)
            
        elif cmd == "memory":
            self._memory_command(args)
            
        elif cmd == "toggle":
            self._toggle_feature(args)
            
        else:
            self._log(f"Unknown command: {cmd}", "error")
            self._log(f"Type 'help' for available commands.", "info")
    
    def _show_help(self, command: Optional[str] = None) -> None:
        """Show help information"""
        if command and command in self.commands:
            cmd_info = self.commands[command]
            self._log(f"Help for '{command}':", "info")
            self._log(f"  {cmd_info['help']}", "info")
            self._log(f"  Usage: {cmd_info['usage']}", "info")
        else:
            self._log("Available commands:", "info")
            for cmd, info in self.commands.items():
                self._log(f"  {cmd}: {info['help']}", "info")
            self._log("Type 'help <command>' for more information on a specific command.", "info")
    
    def _connect_target(self, args: List[str]) -> None:
        """Connect to a target binary"""
        if not args:
            self._log("Error: No binary specified", "error")
            self._log("Usage: connect <binary> [args]", "info")
            return
            
        binary_path = args[0]
        binary_args = args[1:] if len(args) > 1 else []
        
        if not os.path.exists(binary_path):
            self._log(f"Error: Binary not found: {binary_path}", "error")
            return
            
        try:
            # Disconnect if already connected
            if self.process:
                self._disconnect_target()
                
            # Start the process
            self._log(f"Starting process: {binary_path} {' '.join(binary_args)}", "info")
            
            # Use subprocess
            self.process = subprocess.Popen(
                [binary_path] + binary_args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            self.target_binary = binary_path
            self.connected = True
            self._update_status("Status", f"Connected to {os.path.basename(binary_path)}")
            self._update_status("Target", binary_path)
            self._update_status("Connected", "Yes")
            
            # Start a thread to read process output
            threading.Thread(target=self._read_process_output, daemon=True).start()
            
            self._log(f"Connected to {binary_path}", "success")
            
        except Exception as e:
            self._log(f"Error connecting to target: {e}", "error")
    
    def _disconnect_target(self) -> None:
        """Disconnect from the current target"""
        if not self.process:
            self._log("Not connected to any target", "warning")
            return
            
        try:
            self._log("Disconnecting from target", "info")
            self.process.terminate()
            self.process = None
            self.connected = False
            self._update_status("Status", "Ready")
            self._update_status("Connected", "No")
            self._log("Disconnected from target", "success")
            
        except Exception as e:
            self._log(f"Error disconnecting from target: {e}", "error")
    
    def _read_process_output(self) -> None:
        """Read output from the connected process"""
        if not self.process:
            return
            
        try:
            # Read from stdout
            for line in iter(self.process.stdout.readline, ''):
                if line:
                    self._log(f"[Process] {line.rstrip()}", "info")
            
            # Read from stderr
            for line in iter(self.process.stderr.readline, ''):
                if line:
                    self._log(f"[Process Error] {line.rstrip()}", "error")
                    
            # Process has ended
            if self.process:
                exit_code = self.process.poll()
                self._log(f"Process exited with code {exit_code}", "warning")
                self.process = None
                self.connected = False
                self._update_status("Status", "Ready")
                self._update_status("Connected", "No")
                
        except Exception as e:
            self._log(f"Error in process output thread: {e}", "error")
    
    def _start_gdb(self, args: List[str]) -> None:
        """Start GDB with the current target"""
        if not self.target_binary:
            self._log("Error: No target binary specified", "error")
            self._log("Please connect to a target first", "info")
            return
            
        try:
            # Kill existing GDB process if running
            if self.gdb_process:
                self._log("Terminating existing GDB process", "warning")
                self.gdb_process.terminate()
                self.gdb_process = None
                
            # Start GDB
            gdb_args = ["gdb", self.target_binary] + args
            self._log(f"Starting GDB: {' '.join(gdb_args)}", "info")
            
            # Start GDB in a new terminal window
            if sys.platform == "darwin":  # macOS
                subprocess.Popen(["osascript", "-e", f'tell app "Terminal" to do script "cd {os.getcwd()} && {" ".join(gdb_args)}"'])
            elif sys.platform == "linux":
                subprocess.Popen(["x-terminal-emulator", "-e", f"cd {os.getcwd()} && {' '.join(gdb_args)}"])
            else:
                self._log(f"Opening GDB in current terminal", "warning")
                self.gdb_process = subprocess.Popen(gdb_args)
                
            self._update_status("GDB", "Running")
            self._log(f"GDB started for {self.target_binary}", "success")
            
        except Exception as e:
            self._log(f"Error starting GDB: {e}", "error")
    
    def _check_security(self, args: List[str]) -> None:
        """Check security features of a binary (simplified)"""
        binary_path = args[0] if args else self.target_binary
        
        if not binary_path:
            self._log("Error: No binary specified", "error")
            self._log("Please specify a binary or connect to a target first", "info")
            return
            
        if not os.path.exists(binary_path):
            self._log(f"Error: Binary not found: {binary_path}", "error")
            return
            
        try:
            self._log(f"Checking security features of {binary_path}", "info")
            
            # Use readelf and objdump to check security features
            result = subprocess.run(["readelf", "-a", binary_path], capture_output=True, text=True)
            readelf_output = result.stdout
            
            # Check for PIE
            pie = "Type: DYN" in readelf_output
            
            # Check for stack canary
            canary = "__stack_chk_fail" in readelf_output
            
            # Check for NX
            nx = "GNU_STACK" in readelf_output and "RWE" not in readelf_output
            
            # Format the output
            self._log(f"Security features of {binary_path}:", "info")
            self._log(f"  PIE:          {'Enabled' if pie else 'Disabled'}", "info")
            self._log(f"  Stack Canary: {'Enabled' if canary else 'Disabled'}", "info")
            self._log(f"  NX:           {'Enabled' if nx else 'Disabled'}", "info")
            
        except Exception as e:
            self._log(f"Error checking security features: {e}", "error")
    
    def _show_info(self, args: List[str]) -> None:
        """Show information about a topic"""
        if not args:
            # Show general info
            self._log("PwnLookup Information:", "info")
            self._log("  Use 'info <topic>' to get more information about a specific topic.", "info")
            self._log("  Available topics: binary, process, gdb, commands", "info")
            return
            
        topic = args[0].lower()
        
        if topic == "binary" and self.target_binary:
            try:
                # Get basic file info
                file_info = subprocess.run(["file", self.target_binary], capture_output=True, text=True).stdout
                
                self._log("Binary Information:", "info")
                self._log(f"  Path: {self.target_binary}", "info")
                self._log(f"  File Info: {file_info.strip()}", "info")
                
            except Exception as e:
                self._log(f"Error getting binary information: {e}", "error")
                
        elif topic == "process":
            if not self.process:
                self._log("No process is currently running", "warning")
                return
                
            try:
                pid = self.process.pid
                status = "Running" if self.process.poll() is None else f"Exited ({self.process.poll()})"
                
                self._log("Process Information:", "info")
                self._log(f"  Binary: {self.target_binary}", "info")
                self._log(f"  PID: {pid}", "info")
                self._log(f"  Status: {status}", "info")
                
            except Exception as e:
                self._log(f"Error getting process information: {e}", "error")
                
        elif topic == "gdb":
            if not self.gdb_process:
                self._log("GDB is not currently running", "warning")
                return
                
            self._log("GDB Information:", "info")
            self._log(f"  Target: {self.target_binary}", "info")
            self._log(f"  Status: Running", "info")
            
        elif topic == "commands":
            self._show_help()
            
        else:
            self._log(f"Unknown info topic: {topic}", "error")
            self._log("Available topics: binary, process, gdb, commands", "info")
    
    def _run_shell_command(self, args: List[str]) -> None:
        """Run a shell command"""
        if not args:
            self._log("Error: No command specified", "error")
            self._log("Usage: shell <command>", "info")
            return
            
        command = " ".join(args)
        
        try:
            self._log(f"Running shell command: {command}", "info")
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            
            output = result.stdout
            error = result.stderr
            exit_code = result.returncode
            
            if output:
                self._log(f"Output:", "info")
                for line in output.splitlines():
                    self._log(f"  {line}", "info")
            if error:
                self._log(f"Error:", "error")
                for line in error.splitlines():
                    self._log(f"  {line}", "error")
            self._log(f"Exit code: {exit_code}", "info")
            
        except Exception as e:
            self._log(f"Error running shell command: {e}", "error")
    
    def _send_to_process(self, data: str) -> None:
        """Send data to the connected process"""
        if not self.process:
            self._log("Error: Not connected to any process", "error")
            return
            
        try:
            self._log(f"Sending to process: {data}", "info")
            self.process.stdin.write(data + "\n")
            self.process.stdin.flush()
            
        except Exception as e:
            self._log(f"Error sending data to process: {e}", "error")
    
    def _hexdump_memory(self, args: List[str]) -> None:
        """Dump memory in hex format"""
        if not self.process:
            self._log("Error: Not connected to any process", "error")
            return
            
        if not args:
            self._log("Error: No address specified", "error")
            self._log("Usage: hexdump <address> [length]", "info")
            return
            
        try:
            # Parse address
            address = int(args[0], 0)
            length = int(args[1], 0) if len(args) > 1 else 128
            
            # Limit length to reasonable value
            if length > 1024:
                self._log("Warning: Limiting length to 1024 bytes", "warning")
                length = 1024
                
            # Read memory using GDB
            if sys.platform == "darwin":  # macOS
                gdb_cmd = f"gdb -p {self.process.pid} -batch -ex 'dump binary memory /tmp/pwnlookup_dump.bin {hex(address)} {hex(address+length)}' -ex 'quit'"
                subprocess.run(gdb_cmd, shell=True, capture_output=True)
                
                # Read the dumped memory
                with open("/tmp/pwnlookup_dump.bin", "rb") as f:
                    memory_data = f.read()
                    
                # Remove the temporary file
                os.remove("/tmp/pwnlookup_dump.bin")
            else:
                # On Linux, we can read process memory directly
                mem_path = f"/proc/{self.process.pid}/mem"
                with open(mem_path, "rb") as f:
                    f.seek(address)
                    memory_data = f.read(length)
            
            # Display the memory in hex format
            self._log(f"Memory dump at {hex(address)} ({length} bytes):", "info")
            
            # Format the hex dump
            for i in range(0, len(memory_data), 16):
                chunk = memory_data[i:i+16]
                hex_values = " ".join(f"{b:02x}" for b in chunk)
                ascii_values = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                
                # Pad hex values if needed
                if len(chunk) < 16:
                    hex_values += "   " * (16 - len(chunk))
                
                self._log(f"{address+i:08x}:  {hex_values}  |{ascii_values}|", "info")
                
        except Exception as e:
            self._log(f"Error dumping memory: {e}", "error")
            import traceback
            for line in traceback.format_exc().splitlines():
                self._log(line, "error")
    
    def _memory_command(self, args: List[str]) -> None:
        """Read or write process memory"""
        if not self.process:
            self._log("Error: Not connected to any process", "error")
            return
            
        if not args:
            self._log("Error: No operation specified", "error")
            self._log("Usage: memory [read|write] <address> [value]", "info")
            return
            
        operation = args[0].lower()
        
        if operation == "read":
            if len(args) < 2:
                self._log("Error: No address specified", "error")
                self._log("Usage: memory read <address> [length]", "info")
                return
                
            try:
                address = int(args[1], 0)
                length = int(args[2], 0) if len(args) > 2 else 8
                
                # Use hexdump to read memory
                self._hexdump_memory([hex(address), str(length)])
                
            except Exception as e:
                self._log(f"Error reading memory: {e}", "error")
                
        elif operation == "write":
            if len(args) < 3:
                self._log("Error: Missing address or value", "error")
                self._log("Usage: memory write <address> <value>", "info")
                return
                
            try:
                address = int(args[1], 0)
                value = args[2]
                
                # Check if value is a string or hex
                if value.startswith("0x"):
                    # Hex value
                    data = bytes.fromhex(value[2:])
                else:
                    # String value
                    data = value.encode()
                
                # Write memory using GDB
                if sys.platform == "darwin":  # macOS
                    # Create a temporary file with the data
                    with open("/tmp/pwnlookup_data.bin", "wb") as f:
                        f.write(data)
                    
                    # Use GDB to write the data
                    gdb_cmd = f"gdb -p {self.process.pid} -batch -ex 'restore /tmp/pwnlookup_data.bin binary {hex(address)}' -ex 'quit'"
                    subprocess.run(gdb_cmd, shell=True, capture_output=True)
                    
                    # Remove the temporary file
                    os.remove("/tmp/pwnlookup_data.bin")
                else:
                    # On Linux, we can write process memory directly
                    mem_path = f"/proc/{self.process.pid}/mem"
                    with open(mem_path, "wb") as f:
                        f.seek(address)
                        f.write(data)
                
                self._log(f"Memory written at {hex(address)} ({len(data)} bytes)", "success")
                
            except Exception as e:
                self._log(f"Error writing memory: {e}", "error")
                import traceback
                for line in traceback.format_exc().splitlines():
                    self._log(line, "error")
        else:
            self._log(f"Unknown memory operation: {operation}", "error")
            self._log("Available operations: read, write", "info")
    
    def _toggle_feature(self, args: List[str]) -> None:
        """Toggle UI features"""
        if not args:
            self._log("Error: No feature specified", "error")
            self._log("Usage: toggle [hex|help]", "info")
            return
            
        feature = args[0].lower()
        
        if feature == "hex":
            self.hex_view = not self.hex_view
            self._log(f"Hex view {'enabled' if self.hex_view else 'disabled'}", "success")
            
        elif feature == "help":
            self.show_help_panel = not self.show_help_panel
            self._log(f"Help panel {'enabled' if self.show_help_panel else 'disabled'}", "success")
            
        else:
            self._log(f"Unknown feature: {feature}", "error")
            self._log("Available features: hex, help", "info")
    
    def run(self) -> None:
        """Run the UI"""
        self._log("Starting PwnLookup UI", "info")
        self._update_status("Status", "Ready")
        
        # Display welcome message
        welcome = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗ ██╗    ██╗███╗   ██╗██╗      ██████╗  ██████╗ ██╗  ║
║   ██╔══██╗██║    ██║████╗  ██║██║     ██╔═══██╗██╔═══██╗██║  ║
║   ██████╔╝██║ █╗ ██║██╔██╗ ██║██║     ██║   ██║██║   ██║██║  ║
║   ██╔═══╝ ██║███╗██║██║╚██╗██║██║     ██║   ██║██║   ██║╚═╝  ║
║   ██║     ╚███╔███╔╝██║ ╚████║███████╗╚██████╔╝╚██████╔╝██╗  ║
║   ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

Welcome to PwnLookup Interactive UI!
Type 'help' for available commands or press F1 to toggle help panel.
"""
        for line in welcome.splitlines():
            self._log(line, "success")
        
        # Main UI loop
        while self.running:
            try:
                # Format the prompt based on connection status
                if self.connected:
                    prompt_str = f"<ansired>pwnlookup</ansired> <ansigreen>{os.path.basename(self.target_binary)}</ansigreen> > "
                else:
                    prompt_str = "<ansired>pwnlookup</ansired> > "
                
                # Get user input
                command = self.session.prompt(
                    HTML(prompt_str),
                    pre_run=self._pre_prompt
                )
                
                # Check if command is None (Ctrl+C or Ctrl+D)
                if command is None:
                    self.running = False
                    continue
                
                # Check if it's a command or data to send
                if command.startswith("!"):
                    # Send data to the process
                    self._send_to_process(command[1:])
                else:
                    # Process the command
                    self._process_command(command)
                    
            except KeyboardInterrupt:
                self._log("Keyboard interrupt received", "warning")
                if self.process:
                    self._log("Terminating process...", "warning")
                    self.process.terminate()
                    self.process = None
                    self.connected = False
                    self._update_status("Connected", "No")
                else:
                    self.running = False
                    
            except EOFError:
                self._log("EOF received, exiting...", "warning")
                self.running = False
                
            except Exception as e:
                self._log(f"Error in main loop: {e}", "error")
                import traceback
                for line in traceback.format_exc().splitlines():
                    self._log(line, "error")
    
    def _pre_prompt(self):
        """Display output before showing the prompt"""
        # Format and display the output
        output = self._format_output()
        console.print(output)
        
        # Display status
        status_panel = Panel(
            self._format_status(),
            title="Status",
            border_style="yellow",
            box=box.ROUNDED,
            width=40
        )
        console.print(status_panel)
        
        # Display help panel if enabled
        if self.show_help_panel:
            help_panel = Panel(
                self._format_help(),
                title="Help (F1 to toggle)",
                border_style="cyan",
                box=box.ROUNDED
            )
            console.print(help_panel)

def main():
    """Main function"""
    try:
        # Display startup message
        print("Starting PwnLookup Interactive UI...")
        
        # Initialize and run the UI
        ui = PwnLookupUI()
        ui.run()
        return 0
    except KeyboardInterrupt:
        print("\nExiting PwnLookup...")
        return 0
    except Exception as e:
        print(f"Error starting PwnLookup: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main()) 