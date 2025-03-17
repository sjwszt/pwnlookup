#!/usr/bin/env python3
"""
PwnLookup - Automated Vulnerability Exploitation Tool
Main script for running the tool
"""

import os
import sys
import argparse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def setup_parser():
    """Set up command line argument parser"""
    parser = argparse.ArgumentParser(
        description='PwnLookup - Automated Vulnerability Exploitation Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Launch interactive UI
  python pwnlookup.py --ui

  # Analyze a local binary
  python pwnlookup.py -f ./target_binary
  
  # Analyze a remote binary with libc and ld specified
  python pwnlookup.py -f ./target_binary -l ./libc.so -d ./ld.so -i 192.168.1.1:1337
  
  # Run specific vulnerability type detection
  python pwnlookup.py -f ./target_binary -t fmt_str
'''
    )
    
    # Required arguments (unless --ui is specified)
    file_arg = parser.add_argument('-f', '--file', help='Target binary file path')
    
    # Optional arguments
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-t', '--type', choices=['fmt_str', 'stack', 'heap', 'all'], default='all',
                        help='Vulnerability type to detect (default: all)')
    parser.add_argument('-l', '--libc', help='Path to libc.so file')
    parser.add_argument('-d', '--ld', help='Path to ld.so file')
    parser.add_argument('-i', '--ip', help='Remote target IP:PORT')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('--timeout', type=int, default=60, help='Analysis timeout in seconds (default: 60)')
    parser.add_argument('--ui', action='store_true', help='Launch interactive UI')
    
    return parser

def main():
    """Main function"""
    parser = setup_parser()
    args = parser.parse_args()
    
    # Set log level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Launch interactive UI if requested
    if args.ui:
        try:
            from pwnlookup_ui import main as ui_main
            return ui_main()
        except ImportError as e:
            logger.error(f"Interactive UI module not found: {e}")
            logger.error("Make sure pwnlookup_ui.py is in the current directory and all dependencies are installed.")
            return 1
    
    # Check if target file is specified
    if not args.file:
        logger.error("Target file is required unless using --ui")
        parser.print_help()
        return 1
    
    # Check if target file exists
    if not os.path.isfile(args.file):
        logger.error(f"Target file not found: {args.file}")
        return 1
    
    # Initialize AEG
    try:
        # Try to import aeg_module
        try:
            from aeg_module import aeg_main
        except ImportError as e:
            logger.error(f"Failed to import aeg_module: {e}")
            logger.error("Make sure all dependencies are installed (angr, pwntools, etc.)")
            logger.error("You can still use the interactive UI with: python pwnlookup.py --ui")
            return 1
            
        logger.info(f"Initializing PwnLookup for target: {args.file}")
        aeg = aeg_main.AEG(args.file)
        
        # Set options
        if args.libc:
            aeg.set_libc(args.libc)
        if args.ld:
            aeg.set_ld(args.ld)
        if args.ip:
            ip, port = args.ip.split(':')
            aeg.set_remote(ip, int(port))
        
        # Run analysis
        logger.info(f"Running vulnerability analysis (type: {args.type})")
        result = aeg.run(vuln_type=args.type, timeout=args.timeout)
        
        # Output results
        if result:
            logger.info("Analysis completed successfully")
            print("\nResults:")
            print(result)
            
            # Save to file if specified
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(str(result))
                logger.info(f"Results saved to: {args.output}")
        else:
            logger.warning("No vulnerabilities found or exploitation failed")
        
        return 0
        
    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        logger.info("You can still use the interactive UI with: python pwnlookup.py --ui")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 