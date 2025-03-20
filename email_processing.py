import os
import json
import email
import logging
from pathlib import Path
from datetime import datetime
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from malware_check import calculate_file_hash, check_hash_malicious

def extract_email_headers(msg):
    """Extract key email headers into a dictionary."""
    headers = {}
    
    # Standard headers
    headers['from'] = msg.get('From', '')
    headers['to'] = msg.get('To', '')
    headers['subject'] = msg.get('Subject', '')
    headers['date_header'] = msg.get('Date', '')
    headers['message_id'] = msg.get('Message-ID', '')
    
    # Security and authentication headers
    headers['return_path'] = msg.get('Return-Path', '')
    headers['dkim'] = msg.get('DKIM-Signature', '')
    headers['spf'] = msg.get('Received-SPF', '')
    headers['dmarc'] = msg.get('DMARC-Filter', '')
    
    # Sender IP extraction
    received_headers = msg.get_all('Received', [])
    sender_ip = None
    for header in received_headers:
        # Look for IP in brackets - common format is "from X (Y [IP]) by Z"
        import re
        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', header)
        if ip_match:
            sender_ip = ip_match.group(1)
            break
    
    headers['sender_ip'] = sender_ip
    
    return headers

def extract_email_address(address_string):
    """Extract email address from a formatted address string."""
    _, email_addr = parseaddr(address_string)
    return email_addr

def process_attachments(msg, email_info):
    """Process email attachments and check for malicious content."""
    malicious_attachments = []
    
    for part in msg.iter_attachments():
        filename = part.get_filename()
        if not filename:
            continue
        
        # Get attachment data
        content = part.get_payload(decode=True)
        if not content:
            continue
            
        # Calculate hash
        file_hash = calculate_file_hash(content)
        
        # Check if hash is malicious
        is_malicious = check_hash_malicious(file_hash)
        
        attachment_info = {
            'filename': filename,
            'hash': file_hash,
            'is_malicious': is_malicious,
            'size': len(content)
        }
        
        if is_malicious:
            malicious_attachments.append(attachment_info)
            
        # Log attachment found
        attachment_logger = logging.getLogger('attachment_log')
        attachment_logger.info(f"Found attachment: {filename} in email from {email_info['from']} - Hash: {file_hash}")
    
    return malicious_attachments

def log_to_json(email_info):
    """Log email information to JSON file."""
    json_path = "/var/log/attachment_hash_malicious.json"
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(json_path), exist_ok=True)
    
    # Prepare the data to be logged
    log_data = {
        'timestamp': datetime.now().isoformat(),
        'sender_email': extract_email_address(email_info.get('from', '')),
        'receiver_email': extract_email_address(email_info.get('to', '')),
        'subject': email_info.get('subject', ''),
        'sender_ip': email_info.get('sender_ip', ''),
        'return_path': email_info.get('return_path', ''),
        'dmarc': email_info.get('dmarc', ''),
        'spf': email_info.get('spf', ''),
        'dkim': bool(email_info.get('dkim')),
        'mailbox': email_info.get('mailbox', ''),
        'malicious_attachments': email_info.get('malicious_attachments', [])
    }
    
    # Check if file exists
    file_exists = os.path.isfile(json_path)
    
    try:
        # If file exists, read existing data
        if file_exists:
            with open(json_path, 'r') as f:
                try:
                    existing_data = json.load(f)
                    if not isinstance(existing_data, list):
                        existing_data = [existing_data]
                except json.JSONDecodeError:
                    # If file is corrupted, start with empty list
                    existing_data = []
        else:
            existing_data = []
        
        # Append new data
        existing_data.append(log_data)
        
        # Write back to file
        with open(json_path, 'w') as f:
            json.dump(existing_data, f, indent=4)
            
        print(f"Successfully logged malicious email info to {json_path}")
        return True
    except Exception as e:
        print(f"Failed to log to JSON file: {str(e)}")
        logging.error(f"Failed to log to JSON file: {str(e)}")
        return False

def process_email_file(file_path):
    """Process an email file and check for malicious attachments."""
    try:
        # Extract the mailbox from the path
        # Typically, the path structure is something like /opt/zimbra/store/0/xx/msg/0-yy.msg
        parts = str(file_path).split('/')
        mailbox_idx = parts.index('store') + 2 if 'store' in parts else -1
        mailbox = None
        
        if mailbox_idx > 0 and mailbox_idx < len(parts):
            try:
                # The mailbox ID might be a number
                mailbox = parts[mailbox_idx]
            except:
                pass
        
        # Read the email file
        with open(file_path, 'rb') as f:
            raw_email = f.read()
        
        # Parse the email
        msg = BytesParser(policy=policy.default).parse(raw_email)
        
        # Extract email headers
        email_info = extract_email_headers(msg)
        
        # Add file metadata
        email_info['file_path'] = str(file_path)
        email_info['file_timestamp'] = datetime.fromtimestamp(file_path.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        
        # Add mailbox information if available
        if mailbox:
            email_info['mailbox'] = mailbox
        
        # Process attachments
        malicious_attachments = process_attachments(msg, email_info)
        
        # If there are malicious attachments, mark the email
        email_info['has_malicious_content'] = len(malicious_attachments) > 0
        email_info['malicious_attachments'] = malicious_attachments
        
        # Log to JSON if malicious content is found
        if email_info['has_malicious_content']:
            log_to_json(email_info)
        
        return email_info
    except Exception as e:
        logging.error(f"Error processing email file {file_path}: {str(e)}")
        print(f"Error processing email file {file_path}: {str(e)}")
        return None