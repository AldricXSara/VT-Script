import base64URLEncode
import validation
import requests


def IP_lookup(ipaddress, apikey):
    baseURL = "https://www.virustotal.com/api/v3/ip_addresses/"

    newURL = baseURL + ipaddress
    headers = {"Accept": "application/json",
               "x-apikey": apikey}
    outList = []
    try:
        response = requests.get(newURL, headers=headers)
        json_new = response.json()
        harmless = json_new['data']['attributes']['last_analysis_stats']['harmless']
        malicious = json_new['data']['attributes']['last_analysis_stats']['malicious']
        suspicious = json_new['data']['attributes']['last_analysis_stats']['suspicious']
        undetected = json_new['data']['attributes']['last_analysis_stats']['undetected']
        total = harmless + malicious + suspicious + undetected
        reputation = " " + str(malicious) + "/" + str(total)
        try:
            owner = json_new['data']['attributes']['as_owner']
        except KeyError as e:
            owner = "No Data"
        try:
            country = json_new['data']['attributes']['country']
        except KeyError as e:
            country = "No Data"
        outList = [ipaddress, "IP Address", owner, country, harmless, malicious, suspicious, undetected, reputation]
        print(outList)
    except requests.exceptions.RequestException as e:
        print("Connection Error")
    except KeyError as e:
        harmless = "No Data"
        malicious = "No Data"
        suspicious = "No Data"
        undetected = "No Data"
        reputation = "No Data"
        owner = "No Data"
        country = "No Data"
        outList = [ipaddress, "IP Address", owner, country, harmless, malicious, suspicious, undetected, reputation]
    return outList


def URL_lookup(urlinput, apikey):
    baseURL = "https://www.virustotal.com/api/v3/urls/"
    newURL = str(baseURL) + str(base64URLEncode.urlencode(urlinput))
    print(str(base64URLEncode.urlencode(urlinput)))
    headers = {
        "accept": "application/json",
        "x-apikey": apikey
    }
    outList = []
    try:
        response = requests.get(newURL, headers=headers)
        json_new = response.json()
        print(json_new)
        if "error" in json_new:
            print(json_new['error']['code'])
        else:
            harmless = json_new['data']['attributes']['last_analysis_stats']['harmless']
            malicious = json_new['data']['attributes']['last_analysis_stats']['malicious']
            suspicious = json_new['data']['attributes']['last_analysis_stats']['suspicious']
            undetected = json_new['data']['attributes']['last_analysis_stats']['undetected']
            country = "Info not supported for data type"
            owner = "Info not supported for data type"
            total = harmless + malicious + suspicious + undetected
            reputation = " " + str(malicious) + "/" + str(total)
            outList = [urlinput, "URL", owner, country, harmless, malicious, suspicious, undetected, reputation]
    except requests.exceptions.RequestException as e:
        print("Connection Error")
    except KeyError as e:
        harmless = "No Data"
        malicious = "No Data"
        suspicious = "No Data"
        undetected = "No Data"
        reputation = "No Data"
        country = "Info not supported for data type"
        owner = "Info not supported for data type"
        outList = [urlinput, "URL", owner, country, harmless, malicious, suspicious, undetected, reputation]
    return outList

def domain_lookup(urlinput, apikey):
    baseURL = "https://www.virustotal.com/api/v3/domains/"
    newURL = str(baseURL) + str(urlinput)
    headers = {
        "accept": "application/json",
        "x-apikey": apikey
    }
    outList = []
    try:
        response = requests.get(newURL, headers=headers)
        json_new = response.json()
        print(json_new)
        if "error" in json_new:
            print(json_new['error']['code'])
        else:
            harmless = json_new['data']['attributes']['last_analysis_stats']['harmless']
            malicious = json_new['data']['attributes']['last_analysis_stats']['malicious']
            suspicious = json_new['data']['attributes']['last_analysis_stats']['suspicious']
            undetected = json_new['data']['attributes']['last_analysis_stats']['undetected']
            total = harmless + malicious + suspicious + undetected
            reputation = " " + str(malicious) + "/" + str(total)
            try:
                owner = json_new['data']['attributes']['last_https_certificate']['subject']['O']
            except KeyError as e:
                try:
                    owner = json_new['data']['attributes']['last_https_certificate']['issuer']['O']
                except KeyError as e:
                    owner = "No Data"
            try:
                country = json_new['data']['attributes']['last_https_certificate']['subject']['C']
            except KeyError as e:
                try:
                    country = json_new['data']['attributes']['last_https_certificate']['issuer']['C']
                except KeyError as e:
                    country = "No Data"
            outList = [urlinput, "Domain", owner, country, harmless, malicious, suspicious, undetected, reputation]
    except requests.exceptions.RequestException as e:
        print("Connection Error")
    except KeyError as e:
        harmless = "No Data"
        malicious = "No Data"
        suspicious = "No Data"
        undetected = "No Data"
        reputation = "No Data"
        owner = "No Data"
        country = "No Data"
        outList = [urlinput, "Domain", owner, country, harmless, malicious, suspicious, undetected, reputation]
    return outList


def hash_lookup(hashInput, apikey, hashtype):
    baseURL = "https://www.virustotal.com/api/v3/files/"
    newURL = str(baseURL)+str(hashInput)
    headers = {
        "accept": "application/json",
        "x-apikey": apikey
    }
    outList = []

    try:
        response = requests.get(newURL, headers=headers)
        json_new = response.json()
        harmless = json_new['data']['attributes']['last_analysis_stats']['harmless']
        malicious = json_new['data']['attributes']['last_analysis_stats']['malicious']
        suspicious = json_new['data']['attributes']['last_analysis_stats']['suspicious']
        undetected = json_new['data']['attributes']['last_analysis_stats']['undetected']
        try:
            owner = json_new['data']['attributes']['crowdsourced_yara_results'][0]['author']
        except KeyError as e:
            owner = "No Data"
        country = "Info not supported for data type"
        total = harmless + malicious + suspicious + undetected
        reputation = " " + str(malicious) + "/" + str(total)
        outList = [hashInput, hashtype, owner, country, harmless, malicious, suspicious, undetected, reputation]
    except requests.exceptions.RequestException as e:
        print("Connection Error")
    except KeyError as e:
        harmless = "No Data"
        malicious = "No Data"
        suspicious = "No Data"
        undetected = "No Data"
        reputation = "No Data"
        owner = "Info not supported for data type"
        country = "Info not supported for data type"
        outList = [hashInput, hashtype, owner, country, harmless, malicious, suspicious, undetected, reputation]
    return outList


def convertHash(hashInput, apikey, hashtype, targettype):
    baseURL = "https://www.virustotal.com/api/v3/files/"
    newURL = str(baseURL) + str(hashInput)
    headers = {
        "accept": "application/json",
        "x-apikey": apikey
    }
    outList = []

    try:
        response = requests.get(newURL, headers=headers)
        json_new = response.json()

        if targettype == hashtype:
            hashconvert = hashInput
        else:
            if targettype == "MD5":
                hashconvert = json_new['data']['attributes']['md5']
            elif targettype =="SHA256":
                hashconvert = json_new['data']['attributes']['sha256']
        outList = [hashInput, hashtype, hashconvert, targettype]
    except requests.exceptions.RequestException as e:
        print("Connection Error")
    except KeyError as e:
        hashconvert = "No Data"
        outList = [hashInput, hashtype, hashconvert, targettype]
    return outList
