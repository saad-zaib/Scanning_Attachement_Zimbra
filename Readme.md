# Zimbra Malicious Email Scanner

This tool monitors Zimbra email store for new emails, checks their attachments for malicious content using MalwareBazaar, and tags malicious emails within Zimbra.

## Features

- Continuously monitors the Zimbra email store for new emails
- Scans email attachments and calculates SHA256 hashes
- Verifies hashes against MalwareBazaar API to detect malicious content
- Tags emails containing malicious attachments with a "MALICIOUS" tag in Zimbra
- Logs all findings for auditing purposes

## File Structure

- `main.py`: Entry point that handles monitoring and orchestration
- `config.py`: Configuration settings and logging setup
- `email_processing.py`: Functions for processing email files and extracting information
- `malware_check.py`: Functions for calculating file hashes and checking against MalwareBazaar
- `zimbra_tagging.py`: Functions for tagging emails in Zimbra
- `zimbra_commands.py`: Helper functions for executing Zimbra shell commands

## Requirements

- Python 3.6+
- Zimbra server with command-line access
- Internet connection for MalwareBazaar API access

## Installation

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Configure the `ZIMBRA_PATH` in `config.py` to point to your Zimbra email store
4. Run the script: `python main.py`

## Logs

The script generates three log files:
- `attachment_found.log`: All attachments that were found
- `malicious_attachment.log`: Attachments identified as malicious
- `zimbra_operations.log`: Operations performed on the Zimbra server

## Usage

Run the script as a user with sufficient permissions to access the Zimbra email store:

```bash
python main.py
```

For production use, consider setting up a service or cron job to ensure the script runs continuously.