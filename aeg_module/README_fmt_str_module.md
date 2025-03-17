# Format String Vulnerability Module

## Overview

The Format String Vulnerability Module is a component of the PwnLookup tool, specifically designed for detecting and exploiting format string vulnerabilities. This module uses symbolic execution and static analysis techniques to automatically discover format string vulnerabilities in binary programs and generate corresponding exploit code.

## Main Features

- **Vulnerability Detection**: Automatically identify format string vulnerability points in programs
- **Vulnerability Analysis**: Analyze the exploitability and impact range of vulnerabilities
- **Exploit Generation**: Generate exploit code for different scenarios
- **Simulation Execution**: Simulate the execution process of format string functions

## Module Components

The Format String Vulnerability Module consists of the following main components:

1. **FmtStrAnalyzer**: Responsible for detecting and analyzing format string vulnerabilities
2. **FmtStrExploit**: Responsible for generating exploit code
3. **FmtStrSimProcedure**: Responsible for simulating the execution of format string functions
4. **FmtStrExploitTemplates**: Provides common exploit templates

## Quick Start

### Install Dependencies

```bash
pip install angr claripy networkx
```

### Basic Usage

```python
# Import necessary modules
from aeg_module.mod_fmt_str import FmtStrAnalyzer, FmtStrExploit

# Detect vulnerabilities
project = angr.Project('target_binary')
analyzer = FmtStrAnalyzer(project)
vulnerabilities = analyzer.find_fmt_str_vulns()

# Generate exploits
exploit = FmtStrExploit('target_binary')
leak_payload, parser = exploit.generate_leak_exploit(target_addr)
write_payload = exploit.generate_write_exploit(target_addr, value)
```

## Documentation

For detailed documentation, please refer to `docs/fmt_str_guide.md`.

## Supported Exploit Types

1. Information Leakage
   - Address leakage
   - String leakage
   - Data leakage

2. Memory Writing
   - Direct writing
   - Short writing
   - Byte writing

3. Advanced Exploitation
   - GOT table overwriting
   - Return address overwriting
   - Stack pivoting
   - System calls
   - Shellcode injection

## Limitations

- The current version mainly supports x86 and x86_64 architectures
- Manual adjustments may be needed for complex format string vulnerabilities
- Additional symbolic execution constraints may be required in certain special cases

## Contribution

We welcome issue reports and improvement suggestions. If you want to contribute code, please ensure:

1. Follow the existing code style
2. Add appropriate test cases
3. Update relevant documentation

## License

This module follows the same license as the PwnLookup tool. 