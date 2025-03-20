import subprocess
import logging

def run_zimbra_command(command):
    """Run a Zimbra command and return the output."""
    zimbra_logger = logging.getLogger('zimbra_log')
    
    try:
        print(f"Executing: {command}")
        zimbra_logger.info(f"Executing: {command}")
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        stdout = stdout.decode('utf-8')
        stderr = stderr.decode('utf-8')

        if process.returncode != 0:
            print(f"Command failed with return code {process.returncode}")
            print(f"Error: {stderr}")
            zimbra_logger.error(f"Command failed: {stderr}")
            return None

        print(f"Command output: {stdout}")
        zimbra_logger.info(f"Command successful")
        return stdout
    except Exception as e:
        print(f"Exception executing command: {e}")
        zimbra_logger.error(f"Exception executing command: {e}")
        return None