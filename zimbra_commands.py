import re
import logging
from config import MALICIOUS_TAG
from zimbra_commands import run_zimbra_command

def search_specific_email(mailbox, email_info):
    """Search for a specific email using Zimbra-compatible search criteria."""
    # Start with a base search using the most reliable criteria
    base_criteria = []

    if email_info.get('from'):
        # Clean up the from address for the search query
        clean_from = email_info['from'].replace('<', '').replace('>', '')
        clean_from = clean_from.replace('"', '\\"')
        base_criteria.append(f'from:"{clean_from}"')

    if email_info.get('subject'):
        # Escape special characters in subject
        clean_subject = email_info['subject'].replace('"', '\\"')
        base_criteria.append(f'subject:"{clean_subject}"')

    # Add date criteria - format MM/DD/YY
    date_criteria = None
    if email_info.get('date_header'):
        # Extract just the date part
        date_parts = email_info['date_header'].split()
        if date_parts:
            date_criteria = date_parts[0]

    if not date_criteria and email_info.get('file_timestamp'):
        # Try to get date from file timestamp
        date_parts = email_info['file_timestamp'].split()
        if date_parts and len(date_parts) > 0:
            # Convert YYYY-MM-DD to MM/DD/YY
            try:
                year, month, day = date_parts[0].split('-')
                date_criteria = f"{month}/{day}/{year[2:]}"
            except:
                pass

    if date_criteria:
        base_criteria.append(f'date:{date_criteria}')
    else:
        # If no date criteria could be determined, use a recent timeframe
        base_criteria.append('after:-1day')

    # Use a two-stage approach:
    # 1. First search with base criteria (from, subject, date)
    base_query = " ".join(base_criteria)
    command = f'su - zimbra -c "zmmailbox -z -m {mailbox} s -t message \'{base_query}\'"'

    print(f"Searching with criteria: {base_query}")
    output = run_zimbra_command(command)

    # Extract message IDs from the search results
    message_ids = extract_all_message_ids(output) if output else []

    # If we found exactly one message, return it
    if len(message_ids) == 1:
        return message_ids[0]

    # If we found multiple messages, try to refine the search
    if len(message_ids) > 1:
        # Try to extract the time from the headers
        email_time = None

        # Extract from date_header
        if email_info.get('date_header'):
            time_parts = email_info['date_header'].split()
            if len(time_parts) > 1:
                email_time = time_parts[1]

        # Or extract from file_timestamp
        if not email_time and email_info.get('file_timestamp'):
            time_parts = email_info['file_timestamp'].split()
            if len(time_parts) > 1:
                email_time = time_parts[1]

        # If we have a time, try to match it with the search results
        if email_time:
            print(f"Trying to match emails with time: {email_time}")
            # We'll need to get the full details of each message to compare times
            for msg_id in message_ids:
                # Get message details
                get_command = f'su - zimbra -c "zmmailbox -z -m {mailbox} gm {msg_id}"'
                msg_details = run_zimbra_command(get_command)

                if msg_details and email_time in msg_details:
                    print(f"Found message with matching time: {msg_id}")
                    return msg_id

        # If we couldn't match by time, try message-id
        if email_info.get('message_id') and email_info['message_id'].strip():
            clean_msgid = email_info['message_id'].replace('<', '').replace('>', '')
            for msg_id in message_ids:
                # Get message details and look for matching message ID
                get_command = f'su - zimbra -c "zmmailbox -z -m {mailbox} gm {msg_id}"'
                msg_details = run_zimbra_command(get_command)

                if msg_details and clean_msgid in msg_details:
                    print(f"Found message with matching Message-ID: {msg_id}")
                    return msg_id

        # If we still can't determine which message, use the most recent one
        print(f"Unable to narrow down messages, using most recent of {len(message_ids)} messages")
        return message_ids[0]

    # If we couldn't find any messages, return None
    print("No matching messages found")
    return None

def extract_all_message_ids(output):
    """Extract all message IDs from search results."""
    if not output:
        return []

    message_ids = []
    lines = output.strip().split('\n')
    content_lines = [line for line in lines if line.strip() and not line.startswith('num:') and not '--' in line]

    # Remove header rows
    for i, line in enumerate(content_lines):
        if "Id  Type" in line:
            content_lines = content_lines[i+1:]
            break

    for line in content_lines:
        match = re.search(r'^\s*\d+\.\s+(\d+)', line)
        if match:
            message_ids.append(match.group(1))

    return message_ids

def check_tag_exists(mailbox, tag):
    """Check if the tag exists for the mailbox."""
    command = f"su - zimbra -c \"zmmailbox -z -m {mailbox} gat\""
    output = run_zimbra_command(command)

    if output is None:
        return False

    return tag in output

def create_tag(mailbox, tag):
    """Create a tag for the mailbox if it doesn't exist."""
    if not check_tag_exists(mailbox, tag):
        print(f"Creating tag {tag} for mailbox {mailbox}")
        command = f"su - zimbra -c \"zmmailbox -z -m {mailbox} ct {tag}\""
        return run_zimbra_command(command) is not None
    else:
        print(f"Tag {tag} already exists for mailbox {mailbox}")
        return True

def check_if_email_already_tagged(mailbox, message_id, tag):
    """Check if a specific email is already tagged with the tag."""
    command = f"su - zimbra -c \"zmmailbox -z -m {mailbox} gm {message_id}\""
    output = run_zimbra_command(command)

    if not output:
        return False

    # Check if the tag appears in the message details
    tag_pattern = f"t=\"{tag}\"|Tag: {tag}"
    return bool(re.search(tag_pattern, output))

def add_tag_to_email(mailbox, message_id, tag):
    """Add the email to the tag if not already tagged."""
    # First check if the email is already tagged
    if check_if_email_already_tagged(mailbox, message_id, tag):
        print(f"Message {message_id} is already tagged with {tag}, skipping")
        return True

    print(f"Adding message {message_id} to tag {tag} for mailbox {mailbox}")
    command = f"su - zimbra -c \"zmmailbox -z -m {mailbox} tm {message_id} {tag}\""
    return run_zimbra_command(command) is not None

def tag_email_with_malicious_content(email_info):
    """Tag an email as malicious in Zimbra."""
    malicious_logger = logging.getLogger('malicious_log')
    
    if not email_info or not email_info.get('has_malicious_content'):
        return False

    mailbox = email_info.get('mailbox')
    if not mailbox:
        print("No mailbox information available for tagging")
        return False

    # Create the MALICIOUS tag if it doesn't exist
    if not create_tag(mailbox, MALICIOUS_TAG):
        print(f"Failed to create {MALICIOUS_TAG} tag for {mailbox}")
        return False

    # Search for the email in Zimbra
    message_id = search_specific_email(mailbox, email_info)
    if not message_id:
        print(f"Could not find email in Zimbra for {mailbox}")
        return False

    # Add the tag to the email
    if add_tag_to_email(mailbox, message_id, MALICIOUS_TAG):
        print(f"Successfully tagged email with {MALICIOUS_TAG} tag in Zimbra")

        # Log detailed information about the malicious content
        malicious_attachments = email_info.get('malicious_attachments', [])
        for attachment in malicious_attachments:
            malicious_logger.info(f"Tagged message with ID {message_id} - Malicious attachment: {attachment['filename']} - Hash: {attachment['hash']}")

        return True
    else:
        print(f"Failed to tag email with {MALICIOUS_TAG} tag in Zimbra")
        return False