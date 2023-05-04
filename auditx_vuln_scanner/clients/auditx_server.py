import requests

def verifyScanId(scanId):
    try:
        res = requests.post("http://localhost:8088/start/scan", json={"scanRunId": scanId})
        if res.status_code == 200:
            return True, res.json()
        return False, {}
    except:
        return False, {}
    
def scanResultCallback(scanResult, scanId):
    try:
        res = requests.post("http://localhost:8088/end/scan", json={"scanRunId": scanId, "scanResult": scanResult})
        if res.status_code == 200:
            return True, res.json()
        return False, {}
    except:
        return False, {}