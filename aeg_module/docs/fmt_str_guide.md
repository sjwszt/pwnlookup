# Format String Vulnerability Detection and Exploitation Guide

This document provides detailed instructions on how to use the format string vulnerability detection and exploitation module in the PwnLookup tool.

## Table of Contents

1. [Overview](#overview)
2. [Installation and Configuration](#installation-and-configuration)
3. [Basic Usage](#basic-usage)
4. [Advanced Features](#advanced-features)
5. [Exploit Templates](#exploit-templates)
6. [Best Practices](#best-practices)
7. [Troubleshooting](#troubleshooting)
8. [API Reference](#api-reference)

## Overview

Format string vulnerability is a common security vulnerability that occurs when a program directly passes user input as a format string parameter to functions like printf. Attackers can exploit format strings to read or modify the program's memory. This module provides automated vulnerability detection and exploit generation capabilities.

### Key Features

- Automatic detection of format string vulnerabilities
- Generation of various types of exploit payloads
- Support for multiple architectures and operating systems
- Rich exploit templates
- Integration with symbolic execution engine for in-depth analysis

## Installation and Configuration

### Dependencies

```bash
pip install angr
pip install claripy
pip install networkx
```

### Configuration Options

Before using this module, you can customize certain behaviors by modifying the configuration file:

```python
# config.py
FMT_STR_CONFIG = {
    'max_steps': 1000,           # Maximum steps for symbolic execution
    'timeout': 60,               # Analysis timeout (seconds)
    'arch_bits': 64,             # Target architecture bits
    'debug_level': 'INFO'        # Log level
}
```

## Basic Usage

### 1. Vulnerability Detection

```python
from aeg_module.mod_fmt_str import FmtStrAnalyzer

# Create analyzer instance
project = angr.Project('target_binary')
analyzer = FmtStrAnalyzer(project)

# Find format string vulnerabilities
vulnerabilities = analyzer.find_fmt_str_vulns()

# Analyze results
for vuln in vulnerabilities:
    print(f"Vulnerability found at: {vuln['location']}")
    print(f"Vulnerability type: {vuln['type']}")
    print(f"Controllable arguments: {vuln['controllable_args']}")
```

### 2. Basic Exploit Generation

```python
from aeg_module.mod_fmt_str import FmtStrExploit

# Create exploit generator instance
exploit = FmtStrExploit('target_binary')

# Generate information leak payload
leak_payload, parser = exploit.generate_leak_exploit(target_addr)

# Generate arbitrary address write payload
write_payload = exploit.generate_write_exploit(target_addr, value)
```

## Advanced Features

### 1. Multi-stage Exploitation

```python
# 1. Leak stage
leak_chain = exploit.templates.leak_chain([
    ('stack', stack_addr),
    ('got', got_addr)
])

# 2. Write stage
write_chain = exploit.templates.got_overwrite('target_func', shell_addr)

# 3. Combine exploit chain
full_chain = leak_chain + write_chain
```

### 2. Custom Format String Templates

```python
# Create custom template
def custom_template(exploit, target):
    # Implement custom exploit logic
    payload = exploit.craft_payload(...)
    return payload

# Register template
exploit.templates.register('custom', custom_template)
```

## Exploit Templates

This module provides the following predefined exploit templates:

1. GOT Table Overwrite
```python
payload = exploit.templates.got_overwrite('puts', system_addr)
```

2. Return Address Overwrite
```python
payload = exploit.templates.ret_addr_overwrite(shell_addr)
```

3. System Call
```python
payload = exploit.templates.system_call('/bin/sh')
```

4. Shellcode Injection
```python
payload = exploit.templates.shellcode_injection(shellcode)
```

## Best Practices

1. Vulnerability Detection
   - Always set reasonable timeout
   - Use whitelist to filter irrelevant functions
   - Save intermediate analysis results

2. Exploit Generation
   - Prefer predefined templates
   - Verify generated payloads
   - Implement error handling mechanisms

3. Debugging and Testing
   - Enable detailed logging
   - Regularly verify exploit effectiveness

## Troubleshooting

Common issues and solutions:

1. Analysis Timeout
   - Increase timeout limit
   - Reduce analysis scope
   - Use more precise symbolic constraints

2. Exploit Failure
   - Check target address validity
   - Verify format string syntax
   - Confirm memory layout information

3. Performance Issues
   - Enable caching mechanism
   - Optimize symbolic execution paths
   - Use parallel analysis

## API Reference

### FmtStrAnalyzer

Main methods:

```python
class FmtStrAnalyzer:
    def find_fmt_str_vulns(self):
        """Find format string vulnerabilities"""
        
    def analyze_controllability(self, addr):
        """Analyze parameter controllability"""
        
    def check_protection(self):
        """Check protection mechanisms"""
```

### FmtStrExploit

Main methods:

```python
class FmtStrExploit:
    def generate_leak_exploit(self, addr, type='address'):
        """Generate information leak exploit"""
        
    def generate_write_exploit(self, addr, value):
        """Generate arbitrary address write exploit"""
        
    def craft_payload(self, fmt, args):
        """Craft format string payload"""
```

### ExploitTemplates

Main templates:

```python
class ExploitTemplates:
    def got_overwrite(self, func_name, target_addr):
        """GOT table overwrite template"""
        
    def ret_addr_overwrite(self, target_addr):
        """Return address overwrite template"""
        
    def system_call(self, command='/bin/sh'):
        """System call template"""
        
    def shellcode_injection(self, shellcode):
        """Shellcode injection template"""
``` 