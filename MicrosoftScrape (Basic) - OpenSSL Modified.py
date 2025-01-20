import pandas as pd
import numpy as np
import sys
import re
import time
import requests
from datetime import datetime
import xml.etree.ElementTree as ET
import urllib3
from urllib3.util.ssl_ import create_urllib3_context
requests.packages.urllib3.disable_warnings()

start = time.time()
advID = int(sys.argv[1])
now = datetime.now()
yearCheck = '-' + now.strftime('%Y') + '-'
# Run metrics map file to load all metric dicts

with open('CVSSmaps - Copy.py') as f:
    exec(f.read())
    f.close()

link = "https://api.msrc.microsoft.com/cvrf/v3.0/document/2025-Jan" # Set the month and year here

# Block for reading excel

#file_loc = "Security Updates - Microsoft Patch Tuesday (11th Jan).xlsx"
#cveList = pd.read_excel(file_loc, index_col=None, na_values=['NA'], usecols='E,K')
#cveList = cveList.drop_duplicates(ignore_index = True)
#cveList = cveList.dropna(subset='Article')

ctx = create_urllib3_context()
ctx.load_default_certs()
ctx.options |= 0x4  # ssl.OP_LEGACY_SERVER_CONNECT

with urllib3.PoolManager(ssl_context=ctx) as http:
    xmlRes = http.request("GET", link) # Query API again to extract the XML


root = ET.fromstring(xmlRes.data)
cvrfBase = '{http://www.icasi.org/CVRF/schema/cvrf/1.1}'
tagBase = '{http://www.icasi.org/CVRF/schema/vuln/1.1}'
prodBase = '{http://www.icasi.org/CVRF/schema/prod/1.1}'

data = {
    'Title': [], 'Vendor': [], 'Release Date': [], 'Product': [], 'Advisory ID': [], 'Impact': [], 'Severity': [], 'CVE': [], 'Vulnerability Description': [], 'Affected Products and Version(s)': [], 'Solution(s)': [], 'References': []
} # Initialize the output dataframe

dataFrame = pd.DataFrame(data)

sevMap = {
'Critical': 'Critical',
'Important': 'High',
'Moderate': 'Medium',
'Low': 'Low'
}

exploitMap = {'Publicly Disclosed': 0, 'Exploited': 1, 'Latest Software Release': 2}

# Get publish date

pubDate = root.find('.//' + cvrfBase + 'InitialReleaseDate').text
pubDate = pubDate.split('T')[0]

for elem in root.findall('.//' + tagBase + 'CVE' + '/..'):

    row = []

    # Get Title 

    title = elem.find('.//' + tagBase + 'Title').text
    if title == None:
        continue
    row.append(title)

    # Append vendor (Same for all Microsoft CVEs)
    vendor = 'Microsoft'
    row.append(vendor)

    # Get Update date

    revisions = elem.findall('.//' + tagBase + 'Revision')
    upDate = revisions[len(revisions) - 1].find('./' + cvrfBase + 'Date').text.split('T')[0]

    d1 = datetime.strptime(pubDate, '%Y-%m-%d')
    d2 = datetime.strptime(upDate, '%Y-%m-%d')
    if d1 > d2:
        continue

    # Add SA release date

    relDate = elem.findall('.//' + cvrfBase + 'Date')
    row.append(relDate[-1].text.split('T')[0])

    # Get all product IDs
    prodIDs = []
    for prod in elem.find('.//' + tagBase + 'Status[@Type="Known Affected"]').findall('./' + tagBase + 'ProductID'):
        prodIDs.append(prod.text)
    
    # Get the product name and product family for each product ID
    prodNames = []
    prodFams = []
    for prod in prodIDs:

        nameElem = root.find('.//' + prodBase + 'FullProductName[@ProductID="' + str(prod) + '"]')
        prodName = nameElem.text
        if prodName not in prodNames: prodNames.append(prodName)
        famElem = root.find('.//' + prodBase + 'FullProductName[@ProductID="' + prod + '"]' + '/..')
        prodFam = famElem.attrib["Name"]
        if prodFam not in prodFams: prodFams.append(prodFam)

    row.append(', '.join(prodFams))

    # Append Advisory ID

    row.append(advID)
    advID += 1

    # Get Impact

    imp = elem.findall('.//' + tagBase + 'Threat[@Type="Impact"]')
    impacts = []
    for i in imp:
        impact = i.find('./' + tagBase + 'Description')
        if impact.text not in impacts and impact.text != None:
            impacts.append(impact.text)

    if len(impacts) > 1:
        impacts = '\n'.join(impacts)
    elif len(impacts) == 1:
        impacts = impacts[0]
    else:
        impacts = ''
    row.append(impacts)

    # Get Severity

    sevElem = elem.find('.//' + tagBase + 'Threat[@Type="Severity"]')
    try:
        severity = sevElem.find('./' + tagBase + 'Description').text
        row.append(sevMap[severity])
    except:
        row.append('')

    # Get CVE ID
    cve = elem.find('.//' + tagBase + 'CVE').text
    #if yearCheck not in cve:
    #    continue
    row.append(cve)

    # Append Vulnerability Description (same as title)

    vulDesc = title
    row.append(vulDesc)

    row.append('\n'.join(prodNames)) # Append affected product names after vul desc due to format

    # Get solutions

    solutions = 'Obtain and install the released security update(s) by visiting the below listed URL(s):'
    solCheck = []
    chars = len(solutions)
    for sol in elem.findall('.//' + tagBase + 'URL'):
        if sol.text != None and sol.text not in solCheck and re.match('https://support.microsoft.com/help/.*', sol.text) == None:
            solutions += '\n' + sol.text.replace(' ', '%20') # if 'KB' in sol.text else ''
            solCheck.append(sol.text)
    if len(solutions) == chars:
        solutions = 'For further information, please visit the URL(s) listed in the References section.'

    row.append(solutions)

    # Add reference (fixed for MS)

    ref = 'https://msrc.microsoft.com/update-guide/vulnerability/' + cve
    row.append(ref)

    dataFrame.loc[len(dataFrame.index)] = row


dataFrame.to_excel('Microsoft_scrape_data (Basic).xlsx', index = False)
end = time.time()
print('Execution time:', str(round(end - start, 2)), 'seconds')