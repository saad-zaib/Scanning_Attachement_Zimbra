#!/usr/bin/env python3
import os
import time
import logging
from pathlib import Path
from config import ZIMBRA_PATH, setup_logging
from email_processing import process_email_file
from zimbra_tagging import tag_email_with_malicious_content

# Setup logging
setup_logging()

# Keep track of processed emails to avoid reprocessing
processed_emails = {}

def scan_directory(processed_files):
    """Scan directory and return set of new files."""
    current_files = set()
    for root, _, files in os.walk(ZIMBRA_PATH):
        for file in files:
            if file.endswith('.msg'):
                file_path = str(Path(root) / file)
                current_files.add(file_path)
    return current_files - processed_files

def cleanup_processed_emails(processed_emails, max_age=86400):
    """Remove old entries from the processed emails dictionary to prevent memory bloat."""
    current_time = time.time()
    keys_to_remove = []

    for key, info in processed_emails.items():
        timestamp = info.get('processed_timestamp') or info.get('tagged_timestamp')
        if timestamp and (current_time - timestamp) > max_age:
            keys_to_remove.append(key)

    for key in keys_to_remove:
        del processed_emails[key]

    if keys_to_remove:
        print(f"Cleaned up {len(keys_to_remove)} old entries from processed emails cache")

def monitor_directory():
    """Continuously monitor directory for new files and process them."""
    print(f"Monitoring {ZIMBRA_PATH} for new emails...")
    processed_files = set()

    try:
        while True:
            # Scan for new email files
            new_files = scan_directory(processed_files)

            for file_path in new_files:
                path_obj = Path(file_path)
                print(f"Processing new email: {path_obj}")

                # Process the email to check for malicious attachments
                email_info = process_email_file(path_obj)

                # If the email has malicious content, tag it in Zimbra
                if email_info and email_info.get('has_malicious_content'):
                    tag_email_with_malicious_content(email_info)

                    # Store information about the processed email
                    processed_emails[file_path] = {
                        'processed_timestamp': time.time(),
                        'tagged_timestamp': time.time(),
                        'mailbox': email_info.get('mailbox'),
                        'subject': email_info.get('subject'),
                        'has_malicious_content': True
                    }
                else:
                    processed_emails[file_path] = {
                        'processed_timestamp': time.time(),
                        'has_malicious_content': False
                    }

                # Add to processed files set
                processed_files.add(file_path)

            # Clean up old entries periodically
            if len(processed_emails) > 1000:  # Arbitrary threshold
                cleanup_processed_emails(processed_emails)

            # Sleep to avoid excessive CPU usage
            time.sleep(1)

    except KeyboardInterrupt:
        print("Monitoring stopped by user.")

    except Exception as e:
        logging.error(f"Error in monitoring loop: {str(e)}")
        print(f"Fatal error in monitoring loop: {str(e)}")

if __name__ == "__main__":
    try:
        # Initialize logging
        print("Starting Zimbra Malicious Email Scanner...")
        logging.info("Starting Zimbra Malicious Email Scanner...")

        # Start monitoring
        monitor_directory()
    except Exception as e:
        logging.error(f"Fatal error: {str(e)}")
        print(f"Fatal error: {str(e)}")