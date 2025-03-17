# PwnLookup - Automated Vulnerability Exploitation Tool

PwnLookup is a powerful tool based on symbolic execution for automated vulnerability detection and exploitation. It helps security researchers and CTF players to automatically discover and exploit vulnerabilities in binary programs.

## Key Features

- **Multiple Vulnerability Types**: Support for format string, stack overflow, heap overflow, and other common vulnerability types
- **Automated Vulnerability Detection**: Leveraging symbolic execution and static analysis to automatically discover vulnerabilities
- **Intelligent Exploit Generation**: Generating effective exploit code based on vulnerability type and program characteristics
- **Interactive UI**: Providing a user-friendly interface for interacting with target binaries
- **Multiple Architecture Support**: Support for x86, x86_64, and other common architectures

## Installation

### Dependencies

```bash
# Install dependencies using pip
pip install -r requirements.txt
```

### Installation from Source

```bash
git clone https://github.com/yourusername/pwnlookup.git
cd pwnlookup
pip install -r requirements.txt
```

### Using Docker

```bash
# Build the Docker image
docker build -t pwnlookup .

# Run the interactive UI
docker run -it pwnlookup

# Run with a specific binary
docker run -it -v /path/to/binaries:/binaries pwnlookup -f /binaries/target_binary
```

## Quick Start

### Interactive UI

```bash
# Launch the interactive UI
python pwnlookup.py --ui

# Or directly run the UI script
python pwnlookup_ui.py
```

### Command Line Usage

```bash
# Analyze a local binary
python pwnlookup.py -f ./target_binary

# Analyze a remote binary with libc and ld specified
python pwnlookup.py -f ./target_binary -l ./libc.so -d ./ld.so -i 192.168.1.1:1337

# Run specific vulnerability type detection
python pwnlookup.py -f ./target_binary -t fmt_str
```

### API Usage

```python
from aeg_module import aeg_main

# Create an instance
aeg = aeg_main.AEG('target_binary')

# Run vulnerability detection and exploit generation
result = aeg.run()

# Output results
print(result)
```

## Module Description

- **pwnlookup.py**: Main entry point for command-line usage
- **pwnlookup_ui.py**: Interactive UI for easier interaction with binaries
- **aeg_module/aeg_main.py**: Main module providing AEG class and core functionality
- **aeg_module/mod_fmt_str.py**: Format string vulnerability detection and exploitation module
- **aeg_module/mod_exploit.py**: General vulnerability exploitation module
- **aeg_module/mod_leak.py**: Information leakage module
- **aeg_module/mod_sim_procedure.py**: Simulation execution module
- **aeg_module/mod_technique.py**: Vulnerability exploitation technique module
- **aeg_module/utils.py**: Utility function module

## Documentation

For detailed documentation, please refer to the documentation files in the `aeg_module/docs/` directory.

## Contribution

We welcome issue reports and improvement suggestions. If you want to contribute code, please ensure:

1. Follow the existing code style
2. Add appropriate test cases
3. Update relevant documentation

## License

This project is licensed under the GNU General Public License v3.0. See the LICENSE file for details.

## Acknowledgements

- [angr](https://github.com/angr/angr) - Symbolic execution engine
- [pwntools](https://github.com/Gallopsled/pwntools) - CTF toolkit
- [prompt_toolkit](https://github.com/prompt-toolkit/python-prompt-toolkit) - Interactive command line interface
- [rich](https://github.com/Textualize/rich) - Rich text formatting in the terminal
