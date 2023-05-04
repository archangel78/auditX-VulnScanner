import os
import shutil
import sqlite3
import win32crypt
from Crypto.Cipher import AES

import auditx_vuln_scanner.models.registry as models
import auditx_vuln_scanner.scanner.browser_scanner.browser_util as browser_util

def check_saved_password_strength(chrome_installation):
    output = {
        "result" : False,
        "error": "",
        "meta": []
    }
    for profile in chrome_installation.profiles:
        try:
            shutil.copy(os.path.join(chrome_installation.installation_directory, profile, "Login Data"), os.getcwd())
            with sqlite3.connect("Login Data") as conn:
                cursor = conn.cursor()
                cursor.execute(models.SQLITE_SELECT_STATEMENTS.SELECT_SAVED_PASSWORDS)
                rows = cursor.fetchall()
                for row in rows:
                    password = decrypt_saved_password(row[2], chrome_installation.master_password)
                    if len(password) > 0:
                        password_score = browser_util.get_password_score(password)
                        if password_score < models.SCAN_CONFIG.MINIMUM_PASSWORD_SCORE:
                            output["result"] = True
                            output["meta"].append({"profile": profile, "password_score": password_score, "browser": chrome_installation.browser_name, "password": password[0] + "*"*5 + password[-1], "website": row[0], "username": row[1]})
        except Exception as error:
            print(f"[Error] while scanning profile {profile} for weak passwords: {error}")
    return output

def decrypt_saved_password(password, key):
    try:
        iv = password[3:15]
        password = password[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(password)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            return None