from auditx_vuln_scanner.util import util
import auditx_vuln_scanner.models.registry as models
from auditx_vuln_scanner.scanner.os_scans import get_system_meta
from auditx_vuln_scanner.scanner.browser_scanner import browser_fetcher
from auditx_vuln_scanner.scanner.browser_scanner import browser_util

def initiate_scan(meta):
    genericMeta = util.getMergedJson(get_system_meta(), {"employee_name": meta["empName"]})
    scan_results = {}
    for os_plugin in models.OS_PLUGIN_HANDLERS:
        print(f"[-] Scanning plugin: {os_plugin}")
        scanResult = models.OS_PLUGIN_HANDLERS[os_plugin](genericMeta)
        if scanResult["result"]:
            scan_results[os_plugin] = scanResult
    
    chrome_installation = browser_fetcher.get_chrome_installation()
    if chrome_installation:
        for browser_plugin in models.BROWSER_PLUGIN_HANDLERS:
            print(f"[-] Scanning plugin: {browser_plugin}")
            scanResult = models.BROWSER_PLUGIN_HANDLERS[browser_plugin](chrome_installation)
            if scanResult["result"]:
                scan_results[browser_plugin] = scanResult
        browser_util.browser_scan_cleanup()
    return scan_results