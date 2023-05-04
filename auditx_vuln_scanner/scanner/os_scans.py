import winreg
import platform
import getpass
import json
import socket
import auditx_vuln_scanner.models.registry as models
from auditx_vuln_scanner.util import util

def get_system_meta():
    system_info = {}
    system_info['os'] = platform.system()
    system_info['os_release'] = platform.release()
    system_info['os_version'] = platform.version()
    system_info['python_version'] = platform.python_version()
    system_info['user'] = getpass.getuser()
    system_info['hostname'] = socket.gethostname()
    system_info['processor'] = platform.processor()
    system_info['machine'] = platform.machine()
    system_info['node'] = platform.node()
    
    return system_info

def check_secure_boot_disabled(genericMeta):
    try:
        result = {}
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, models.REGISTRY_KEYS.SECURE_BOOT_REGISTRY_KEY, 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(registry_key, models.REGISTRY_SUB_KEYS.SECURE_BOOT_ENABLED)
        if value:
            result = models.GENERIC_NEGATIVE_RESPONSE 
        else:
            result = models.GENERIC_POSITIVE_RESPONSE
        return util.getMergedJson(result, {"meta": [genericMeta]})
    except WindowsError as e:
        print(f"[ERROR] Could not read secure boot data from registry: {e}")
        return {"result": False, "error": {"message": str(e)}}
    finally:
        winreg.CloseKey(registry_key)

def check_system_firewall_disabled(genericMeta):
    try:
        result = {}
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, models.REGISTRY_KEYS.SYSTEM_FIREWALL_POLICY, 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, models.REGISTRY_SUB_KEYS.SYSTEM_FIREWALL_ENABLED)
        winreg.CloseKey(key)

        if value:
            result = models.GENERIC_NEGATIVE_RESPONSE 
        else:
            result = models.GENERIC_POSITIVE_RESPONSE
        return util.getMergedJson(result, {"meta": [genericMeta]})
    except WindowsError as e:
        print(f"[ERROR] Unable to access firewall settings: {e}")
        return {"result": False, "error": {"message": str(e)}}
    finally:
        winreg.CloseKey(key)

def check_user_access_control_disabled(genericMeta):
    try:
        result = {}
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, models.REGISTRY_KEYS.SYSTEM_POLICY_KEY, 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, models.REGISTRY_SUB_KEYS.USER_ACCESS_CONTROL_ENABLED)
        
        if value:
            result = models.GENERIC_NEGATIVE_RESPONSE 
        else:
            result = models.GENERIC_POSITIVE_RESPONSE
        return util.getMergedJson(result, {"meta": [genericMeta]})
    except WindowsError as e:
        print(f"[ERROR] Unable to access firewall settings: {e}")
        return {"result": False, "error":{"message": str(e)}}
    finally:
        winreg.CloseKey(key)
