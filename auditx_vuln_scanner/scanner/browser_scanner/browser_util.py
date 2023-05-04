import os
import re

import auditx_vuln_scanner.models.registry as models

def get_password_score(password):
    length = len(password)
    score = 0
    if length > 8:
        score += length * 4

    if re.search("[a-z]", password):
        score += 10
    else:
        score -= 10

    if re.search("[A-Z]", password):
        score += 20
    else:
        score -= 10

    if re.search("[0-9]", password):
        score += 20
    else:
        score -= 10

    if re.search("[!@#$%^&*()]", password):
        score += 20
    else:
        score -= 10

    if re.search(r"(\w)\1{2,}", password):
        score -= 20

    return min(max(score, 0), 100)

def browser_scan_cleanup(): 
    for file in models.BROWSER_CLEANUP_FILES:
        if os.path.exists(file):
            os.remove(file)
