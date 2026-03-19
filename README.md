# Basic Network Scanner

A command-line network scanner built in Python.
Developed as a cybersecurity learning project.

## Features
- TCP port scanning (multi-threaded)
- Service and banner detection
- OS fingerprinting via TTL
- JSON and TXT report export
- Clean CLI with argparse

## Requirements
Python 3.x
pip install tabulate

## Usage

# Basic scan
python scanner.py -t 127.0.0.1 -p 1-500

# Save as text report
python scanner.py -t 127.0.0.1 -p 1-500 -o txt

# Skip OS detection
python scanner.py -t 127.0.0.1 -p 1-500 --no-os

# Help
python scanner.py --help

## Disclaimer
This tool is for educational purposes and
authorized network testing only. Do not scan
networks you don't own or have permission to test.