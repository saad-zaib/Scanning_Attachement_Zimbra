# json_logger.py
import json
import logging
import os
from datetime import datetime
from config import JSON_LOG_PATH

def log_malicious_attachment(email_info, attachment_info):
    """
    Log detailed information about malicious attachments to a JSON file.
    
    Args:
        email_info (dict): Information about the email containing the malicious attachment
        attachment_info (dict): Information about the malicious attachment
    """
    try:
        # Create log directory if it doesn't exist
        os.makedirs(os.path.dirname(JSON_LOG_PATH), exist_ok=True)
        
        # Prepare the log entry
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "sender_email": email_info.get('from', 'unknown'),
            "receiver_email": email_info.get('mailbox', 'unknown'),
            "sender_ip": extract_sender_ip(email_info.get('headers', '')),
            "email_subject": email_info.get('subject', 'unknown'),
            "file_name": attachment_info.get('filename', 'unknown'),
            "file_hash": attachment_info.get('hash', 'unknown'),
            "message_id": email_info.get('message_id', 'unknown'),
            "email_path": email_info.get('email_path', 'unknown'),
            "detection_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Append to the JSON file
        with open(JSON_LOG_PATH, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
            
        logging.info(f"Logged malicious attachment information to {JSON_LOG_PATH}")
        
    except Exception as e:
        logging.error(f"Error logging to JSON file: {str(e)}")


def extract_sender_ip(headers):
    """
    Extract sender's IP address from email headers.
    
    Args:
        headers (str): Email headers
        
    Returns:
        str: Sender's IP address or 'unknown'
    """
    import re
    
    # Common header patterns that might contain IP addresses
    ip_patterns = [
        r'Received: from.*?\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]',
        r'X-Originating-IP: \[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?',
        r'X-Sender-IP: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    ]
    
    for pattern in ip_patterns:
        match = re.search(pattern, headers)
        if match:
            return match.group(1)
    
    return "unknown"