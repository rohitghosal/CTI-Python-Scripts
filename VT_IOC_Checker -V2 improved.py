import time
import requests
import csv
import base64
from datetime import datetime
import urllib3
from urllib3.util.ssl_ import create_urllib3_context

requests.packages.urllib3.disable_warnings()

url = "https://www.virustotal.com/api/v3/"
client = requests.session()
client.verify = False
iocErrors = []
apikey = "55c21b92abb784c1c0280a2dc00e13762a13aceaf1827e766dc08b8b4fce3ce8"  # YOUR API KEY #

# ioc = "55c21b92abb784c1c0280a2dc00e13762a13aceaf1827e766dc08b8b4fce3ce8" Rohit
#       "14fe85da38106d50ab08d4d367d6c3d09be651d9258e68ed6bde846e8c59f16a" Rohit
#       "a801551d777acd04350d44a0aa28c3a81a897ab5bdc630c2ba5976eb3c09261e"
#       "886eaf9ae325df963e83430a929b63b43177f86ca159729589fe97ece5dbff49" Aditya
#       "39989a6f86c8654c9db9955979f4b6ac0e1a3954560b7104ae4cd100067e4dce"
#       "8613bc1f38786e1cc71f0efd36943de19ca7d7ac3257814bfaf74d99b7afd169"
#       "03022fc3f4804c8ab6479454300793ab690d941d2a59c08ad4deda8d7d25a3b0"
#       "2c9d05a71eca9e8898fbb75f9094d20e0f1ac4338e30e64afc9a80b8b1850c64" Sunetra
#       "64ded715d6ec248335307fa9552190a6180ee96dc45ff5c5e593776b17ff4349" Sunetra
#       "be51fd9a72603c5974160a69ba7d31db797e31c6f71491a4d7412189a2c4c3d9" Hrishikesh

def reanalyze(ioc, url):
    try:
        if '.' in ioc and '/' in ioc:  # IOC is a URL
            ioc = ioc.replace('[', '').replace(']', '')
            payload = "url=" + ioc
            url = url + 'urls'
            headers = {
                "accept": "application/json",
                "x-apikey": apikey,
                "content-type": "application/x-www-form-urlencoded"
            }
            response = client.post(url, data=payload, headers=headers)
        elif '.' not in ioc:  # IOC is a file
            url = url + 'files/' + ioc + '/analyse'
            headers = {
                "accept": "application/json",
                "x-apikey": apikey
            }
            response = client.post(url, headers=headers)
        else:  # IOC is a domain or an IP
            if ioc.split('.')[0].isnumeric():  # IOC is an IP
                url = url + 'ip_addresses/' + ioc + '/analyse'
            else:  # IOC is a Domain
                url = url + 'domains/' + ioc + '/analyse'
            headers = {
                "accept": "application/json",
                "x-apikey": apikey
            }
            response = client.post(url, headers=headers)
        response.raise_for_status()
        if response.status_code == 200:
            try:
                jsonResponse = response.json()
                print('\n<{!s}> was reanalyzed successfully (Response 200)'.format(ioc))
                return 200
            except ValueError:
                print('\nThere was an error when reanalyzing <{!s}>. Adding IOC to error list....'.format(ioc))
                iocErrors.append(ioc)
                return None
        elif response.status_code == 404:
            print("\n<{!s}> was not found during reanalysis (Response 404)".format(ioc))
            iocErrors.append(ioc)
            return 404
        elif response.status_code == 204:
            print('Received HTTP 204 response. You may have exceeded your API request quota or rate limit.')
            print('https://support.virustotal.com/hc/en-us/articles/115002118525-The-4-requests-minute-limitation-of-the-'
                  'Public-API-is-too-low-for-me-how-can-I-have-access-to-a-higher-quota-')
            return None
    except requests.exceptions.RequestException as err:
        print('Connection timed out. Error is as follows-')
        print(err)
        return None

def report(ioc, url):
    try:
        if '.' in ioc:
            ioc = ioc.replace('[', '').replace(']', '')
            if ioc.split('.')[0].isnumeric():  # IOC is an IP
                url = url + 'ip_addresses/' + ioc
            elif '/' in ioc:  # IOC is a URL
                u = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
                url = url + "urls/" + u
            else:  # IOC is a Domain
                url = url + 'domains/' + ioc 
        else:  # IOC is a file
            url = url + "files/" + ioc

        headers = {
            "accept": "application/json",
            "x-apikey": apikey
        }
        response = client.get(url, headers=headers)
        response.raise_for_status()
        if response.status_code == 200:
            try:
                jsonResponse = response.json()
                print('Report is ready for <{!s}>.'.format(ioc))
                attr = jsonResponse['data']['attributes']
                sha256 = '' if '.' in ioc else attr['sha256']
                sha1 = '' if '.' in ioc else attr['sha1']
                mdFive = '' if '.' in ioc else attr['md5']
                dist = attr['known_distributors']['distributors'][0] if 'known_distributors' in attr.keys() else ''
                t = datetime.fromtimestamp(attr['last_modification_date']).strftime('%Y-%m-%d')
                # t = datetime.fromtimestamp(attr['last_modification_date'], timezone.utc).strftime('%Y-%m-%d')
                as_label = attr['as_owner'] if 'as_owner' in attr else ''
                country = attr['country'] if 'country' in attr else ''
                row = [t, ioc, str(attr['reputation']), str(attr['last_analysis_stats']['malicious']), 
                       str(attr['last_analysis_stats']['harmless']), sha1, sha256, mdFive, dist, as_label, country]
                return row
            except ValueError:
                print('There was an error when fetching report for <{!s}>. Adding IOC to error list....'.format(ioc))
                iocErrors.append(ioc)
                return None
        elif response.status_code == 204:
            print('Received HTTP 204 response. You may have exceeded your API request quota or rate limit.')
            print('https://support.virustotal.com/hc/en-us/articles/115002118525-The-4-requests-minute-limitation-of-the-'
                  'Public-API-is-too-low-for-me-how-can-I-have-access-to-a-higher-quota-')
            return None
    except requests.exceptions.RequestException as err:
        print('Connection timed out. Error is as follows-')
        print(err)
        return None

try:
    rfile = open('results_v2.csv', 'w+', newline='')
    dataWriter = csv.writer(rfile, delimiter=',')
    header = ['Scan Date', 'IOC', 'Reputation', '# of Positive Scans', '# of Negative Scans', 'SHA1', 'SHA256', 'MD5', 'Distributor', 'Autonomous System Label', 'Country']
    dataWriter.writerow(header)
except IOError as ioerr:
    print('Please ensure the results file is closed.')
    print(ioerr)
    quit()

with open("IOCs.txt", "r", encoding='utf-8') as inFile:
    for ioc in inFile:
        ioc = ioc.strip('\n')
        try:
            status = reanalyze(ioc, url)
            if status == 404:
                continue
            time.sleep(45)  # Wait for the reanalysis to complete
            row = report(ioc, url)
            if row:
                dataWriter.writerow(row)
        except Exception as err:
            print('Encountered an error but scanning will continue.', err)

errorFile = open('Errors.txt', 'w+', encoding='utf-8', newline='')
with errorFile:
    write = csv.writer(errorFile)
    write.writerows(iocErrors)
