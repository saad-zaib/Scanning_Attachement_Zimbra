import os
import re
import time
import email
import base64
import logging
from pathlib import Path
from malware_check import calculate_file_hash, check_hash_malicious

def extract_recipient_from_path(path):
    """Extract recipient email from the Zimbra path structure."""
    # Default mailbox for testing
    default_mailbox = "saad@mail.cybersilo.in"

    # Try to extract additional information from path
    try:
        # For more accurate mailbox extraction in production,
        # you might want to create a mapping from Zimbra store paths
        # to actual email addresses
        pass
    except Exception as e:
        logging.warning(f"Could not extract account info from path: {e}")

    # Return the default mailbox
    return default_mailbox

# Modified portion of email_processing.py
def extract_email_info(email_path, msg):
    """Extract information needed to tag the email in Zimbra, including precise date/time."""
    try:
        # Extract recipient from the message
        mailbox = None
        to_header = msg.get('To', '')

        # Extract email address from To header
        to_match = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+)', to_header)
        if to_match:
            mailbox = to_match.group(1)
            print(f"Extracted recipient from To header: {mailbox}")

        # If recipient not found in headers, try to extract from path
        if not mailbox:
            mailbox = extract_recipient_from_path(email_path)
            print(f"Extracted recipient from path: {mailbox}")

        # Get from address and subject for searching
        from_header = msg.get('From', '')
        subject = msg.get('Subject', '')

        # Get date for more precise searching - extract both header date and also file creation time
        date_header = msg.get('Date', '')
        # Get the file modification time as a backup timestamp
        file_timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(email_path)))

        # Parse the date header to a standardized format if possible
        parsed_date = None
        try:
            if date_header:
                # Try to parse the email date header into a datetime object
                parsed_date = email.utils.parsedate_to_datetime(date_header)
                if parsed_date:
                    # Format to a consistent format that works with Zimbra search
                    date_header = parsed_date.strftime("%m/%d/%y %H:%M")
        except Exception as e:
            logging.warning(f"Could not parse date header: {e}")
            date_header = None
            
        # Get all headers as a single string for IP extraction
        headers = ''
        for header, value in msg.items():
            headers += f"{header}: {value}\n"

        return {
            'mailbox': mailbox,
            'from': from_header,
            'subject': subject,
            'date_header': date_header,
            'file_timestamp': file_timestamp,
            'message_id': msg.get('Message-ID', ''),
            'headers': headers,
            'email_path': email_path
        }
    except Exception as e:
        logging.error(f"Error extracting email info from {email_path}: {e}")
        print(f"Error extracting email info: {e}")
        return None

# Modified portion of process_email_file function in email_processing.py
def process_email_file(file_path):
    """Process a single email file, check for attachments, and return email info."""
    attachment_logger = logging.getLogger('attachment_log')
    malicious_logger = logging.getLogger('malicious_log')
    
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
            msg = email.message_from_bytes(file_data)

        # Extract email info for tagging
        email_info = extract_email_info(str(file_path), msg)

        malicious_attachments = []

        # Check for attachments
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue

            filename = part.get_filename()
            is_attachment = filename or (part.get('Content-Disposition') and 'attachment' in part.get('Content-Disposition'))

            if is_attachment:
                if part.get('Content-Transfer-Encoding') == 'base64':
                    attachment_data = base64.b64decode(part.get_payload())
                else:
                    attachment_data = part.get_payload(decode=True)

                file_hash = calculate_file_hash(attachment_data)
                log_entry = f"Filename: {filename}, Hash: {file_hash}, Path: {file_path}"
                attachment_logger.info(log_entry)

                if check_hash_malicious(file_hash):
                    malicious_entry = f"[MALICIOUS] {filename} - Hash: {file_hash} - Email: {file_path}"
                    malicious_logger.info(malicious_entry)
                    print(malicious_entry)
                    
                    attachment_info = {
                        'filename': filename,
                        'hash': file_hash
                    }
                    
                    malicious_attachments.append(attachment_info)
                    
                    # Log to JSON file
                    from json_logger import log_malicious_attachment
                    log_malicious_attachment(email_info, attachment_info)
                else:
                    print(f"[CLEAN] {filename} - Hash: {file_hash}")

        if email_info:
            email_info['malicious_attachments'] = malicious_attachments
            email_info['has_malicious_content'] = len(malicious_attachments) > 0

        return email_info

    except Exception as e:
        logging.error(f"Error processing {file_path}: {str(e)}")
        return None