def run_zimbra_command(command):
    """Run Zimbra command using subprocess and return the output."""
    zimbra_logger = logging.getLogger('zimbra_log')
    
    try:
        # Log the command
        zimbra_logger.info(f"Running command: {command}")
        
        # Run the command
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        # Check if there was an error
        if process.returncode != 0:
            zimbra_logger.error(f"Command failed with return code {process.returncode}: {stderr.decode('utf-8', errors='ignore')}")
            return None
            
        # Return the output
        return stdout.decode('utf-8', errors='ignore')
    except Exception as e:
        zimbra_logger.error(f"Error executing command: {str(e)}")
        return None