def getMergedJson(json1, json2):
    merged_json = json1.copy()
    merged_json.update(json2)
    return merged_json

def printAuditXHeader():
    header_line1 = "=================================================="
    header_line2 = "|          AUDITX VULN SCANNER                  |"
    header_line3 = "=================================================="
    header_line4 = "|                                                |"
    header_line5 = "|  VERSION: 1.0                                   |"
    header_line6 = "|                                                |"
    header_line7 = "=================================================="

    # Print the header
    print(header_line1)
    print(header_line2)
    print(header_line3)
    print(header_line4)
    print(header_line5)
    print(header_line6)
    print(header_line7)

def printScanMeta(meta):
    print("\n"+"==================================================")
    empName = meta["empName"]
    orgName = meta["orgName"]
    print(f"[-] Starting Scan For {empName} ({orgName})")

def printScanResult(scanResult):
    print("\n"+"==================================================\n\n[*] The following issues have been detected on your system: ")
    i = 1
    for plugin in scanResult:
        print(f"\t{i}. "+plugin)
        i += 1