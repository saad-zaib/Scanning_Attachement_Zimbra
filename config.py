import logging
import os

# Configuration
ZIMBRA_PATH = "/opt/zimbra/store"
MALWARE_BAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
MALICIOUS_TAG = "MALICIOUS"
JSON_LOG_PATH = "/var/log/attachment_hash_malicious.json"

def setup_logging():
    """Setup logging configuration."""
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
    
    attachment_logger = logging.getLogger('attachment_log')
    malicious_logger = logging.getLogger('malicious_log')
    zimbra_logger = logging.getLogger('zimbra_log')

    # Ensure log directory exists
    os.makedirs('/var/log', exist_ok=True)

    attachment_handler = logging.FileHandler('attachment_found.log')
    malicious_handler = logging.FileHandler('malicious_attachment.log')
    zimbra_handler = logging.FileHandler('zimbra_operations.log')

    attachment_logger.addHandler(attachment_handler)
    malicious_logger.addHandler(malicious_handler)
    zimbra_logger.addHandler(zimbra_handler)