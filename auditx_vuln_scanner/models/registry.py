import auditx_vuln_scanner.scanner.os_scans as os_scanner
import auditx_vuln_scanner.scanner.browser_scanner.browser_scans as browser_scans

GENERIC_POSITIVE_RESPONSE = {
    "result": True,
    "error": None
}

GENERIC_NEGATIVE_RESPONSE = {
    "result": False,
    "error": None
}

OS_PLUGIN_HANDLERS = {
    "SECURE_BOOT_DISABLED": os_scanner.check_secure_boot_disabled,
    "SYSTEM_FIREWALL_DISABLED": os_scanner.check_system_firewall_disabled,
    "USER_ACCESS_CONTROL_DISABLED": os_scanner.check_user_access_control_disabled
}

BROWSER_PLUGIN_HANDLERS = {
    "WEAK_SAVED_PASSWORDS_IN_BROWSER": browser_scans.check_saved_password_strength
}

BROWSER_CLEANUP_FILES = [
    "Login Data"
]

class BROWSER_INSTALLATION():
    def __init__(self, profiles, installation_directory, master_password, browser_name):
        self.profiles = profiles
        self.installation_directory = installation_directory
        self.master_password = master_password
        self.browser_name = browser_name

class REGISTRY_KEYS():
    SECURE_BOOT_REGISTRY_KEY = "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State"
    SYSTEM_FIREWALL_POLICY = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile"
    SYSTEM_POLICY_KEY = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"

class REGISTRY_SUB_KEYS():
    SECURE_BOOT_ENABLED = "UEFISecureBootEnabled"
    SYSTEM_FIREWALL_ENABLED = "EnableFirewall"
    USER_ACCESS_CONTROL_ENABLED = "EnableLUA"

class SQLITE_SELECT_STATEMENTS():
    SELECT_SAVED_PASSWORDS = "SELECT action_url, username_value, password_value FROM logins"

class SCAN_CONFIG:
    MINIMUM_PASSWORD_SCORE = 75