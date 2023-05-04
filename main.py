from auditx_vuln_scanner.scanner import scanner
from auditx_vuln_scanner.util import util
from auditx_vuln_scanner.clients import auditx_server

def initiate():
    util.printAuditXHeader()
    scanRunId = input("\n[*] Enter Scan Id: ")
    verified, meta = auditx_server.verifyScanId(scanRunId)
    if verified:
        util.printScanMeta(meta)
        scanResult = scanner.initiate_scan(meta)
        if len(scanResult) > 0:
            util.printScanResult(scanResult)
            auditx_server.scanResultCallback(scanResult, scanRunId)
            return
        print("\n"+"==================================================\n\n"+"[*] No issues found on your system")
    else:
        print("[Error] Failed to establish connection with server")

if __name__=="__main__":
    initiate()
    input("\n\n[*] Press enter to exit") 
