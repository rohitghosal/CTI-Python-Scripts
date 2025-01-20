import os
import requests
import pandas as pd
import logging
from dotenv import load_dotenv
import urllib3

# Suppress only the specific InsecureRequestWarning from urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variables from .env file
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def get_general_info(api_key, ioc_type, ioc_value):
    """
    Fetches general information for a given IOC from the OTX API.
    
    Parameters:
    - api_key (str): API key for authenticating with the OTX API.
    - ioc_type (str): Type of IOC (IPv4, domain, url, sha256, sha1, md5).
    - ioc_value (str): Value of the IOC.
    
    Returns:
    - dict: General information about the IOC if successful, None otherwise.
    """
    base_url = "https://otx.alienvault.com/api/v1/indicators"
    
    # Determine the correct endpoint based on the IoC type
    if ioc_type == "IPv4":
        endpoint = f"{base_url}/IPv4/{ioc_value}/general"
    elif ioc_type == "domain":
        endpoint = f"{base_url}/domain/{ioc_value}/general"
    elif ioc_type == "url":
        # URL encode the IoC value for URL
        endpoint = f"{base_url}/url/{requests.utils.quote(ioc_value, safe='')}/general"
    elif ioc_type in ["sha256", "sha1", "md5"]:
        endpoint = f"{base_url}/file/{ioc_value}/general"
    else:
        raise ValueError("Invalid IoC type. Valid types are: IPv4, domain, url, sha256, sha1, md5.")
    
    # Send the request to the OTX API
    headers = {"X-OTX-API-KEY": api_key}
    try:
        response = requests.get(endpoint, headers=headers, verify=False)
        response.raise_for_status()  # Raise HTTPError for bad responses
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching general info for {ioc_type} {ioc_value}: {e}")
        return None

def determine_ioc_type(ioc):
    """
    Determines the type of an IOC based on its value.
    
    Parameters:
    - ioc (str): The IOC value.
    
    Returns:
    - str: The type of the IOC (IPv4, domain, url, sha256, sha1, md5), None if unknown.
    """
    # Check for IPv4 address
    if ioc.count('.') == 3:
        parts = ioc.split('.')
        if all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
            return "IPv4"
    # Check for domain
    if '.' in ioc and not any(c in ioc for c in ' :/'):
        return "domain"
    # Check for file hashes
    if len(ioc) == 64 and all(c in "0123456789abcdef" for c in ioc.lower()):
        return "sha256"
    if len(ioc) == 40 and all(c in "0123456789abcdef" for c in ioc.lower()):
        return "sha1"
    if len(ioc) == 32 and all(c in "0123456789abcdef" for c in ioc.lower()):
        return "md5"
    # Check for URL (a basic check for now)
    if ioc.startswith("http://") or ioc.startswith("https://"):
        return "url"
    return None

def extract_general_info(general_info):
    """
    Extracts relevant general information from the API response.
    
    Parameters:
    - general_info (dict): The API response containing general information.
    
    Returns:
    - dict: Extracted information including Geo Data, Reputation, Malware Samples, URLs, Passive DNS, Whois, and Related Pulses.
    """
    geo_data = general_info.get('geo', {})
    reputation = general_info.get('reputation', {})
    malware_samples = general_info.get('malware', [])
    urls = general_info.get('url_list', [])
    passive_dns = general_info.get('passive_dns', [])
    whois = general_info.get('whois', {})
    related_pulses = general_info.get('pulse_info', {}).get('pulses', [])
    
    return {
        "Geo Data": geo_data,
        "Reputation": reputation,
        "Malware Samples": malware_samples,
        "URLs": urls,
        "Passive DNS": passive_dns,
        "Whois": whois,
        "Related Pulses": related_pulses
    }

def main():
    api_key = os.getenv("OTX_API_KEY")  # Get API key from environment variable
    if not api_key:
        logging.error("API key not found. Please set the OTX_API_KEY environment variable.")
        return
    
    input_file = "OTX_IOCs.txt"
    output_file = "OTX_General_Info_Report_v2.csv"
    
    # Read the IOCs from the input file
    try:
        with open(input_file, 'r') as file:
            iocs = file.readlines()
    except FileNotFoundError:
        logging.error(f"Input file {input_file} not found.")
        return
    
    iocs = [ioc.strip() for ioc in iocs if ioc.strip()]
    
    # Prepare the dataframe for the output CSV
    df = pd.DataFrame(columns=[
        "IOC", "Type", "Geo Data", "Reputation", "Malware Samples", "URLs", "Passive DNS", "Whois",
        "Pulse Link", "Pulse ID", "Pulse Name", "Pulse Description", "Pulse Creation Date", "Pulse Modified Date"
    ])
    
    for ioc in iocs:
        ioc_type = determine_ioc_type(ioc)
        if not ioc_type:
            logging.warning(f"Unknown IOC type for {ioc}, skipping...")
            continue
        
        logging.info(f"Fetching general info for {ioc_type} {ioc}")
        general_info = get_general_info(api_key, ioc_type, ioc)
        if not general_info:
            logging.warning(f"No information found for {ioc}")
            continue
        
        info = extract_general_info(general_info)
        
        if info["Related Pulses"]:
            for pulse in info["Related Pulses"]:
                df = pd.concat([df, pd.DataFrame([{
                    "IOC": ioc,
                    "Type": ioc_type,
                    "Geo Data": info["Geo Data"],
                    "Reputation": info["Reputation"],
                    "Malware Samples": info["Malware Samples"],
                    "URLs": info["URLs"],
                    "Passive DNS": info["Passive DNS"],
                    "Whois": info["Whois"],
                    "Pulse Link": f"https://otx.alienvault.com/pulse/{pulse['id']}",
                    "Pulse ID": pulse['id'],
                    "Pulse Name": pulse['name'],
                    "Pulse Description": pulse['description'],
                    "Pulse Creation Date": pulse['created'],
                    "Pulse Modified Date": pulse['modified']
                }])], ignore_index=True)
        else:
            df = pd.concat([df, pd.DataFrame([{
                "IOC": ioc,
                "Type": ioc_type,
                "Geo Data": info["Geo Data"],
                "Reputation": info["Reputation"],
                "Malware Samples": info["Malware Samples"],
                "URLs": info["URLs"],
                "Passive DNS": info["Passive DNS"],
                "Whois": info["Whois"],
                "Pulse Link": None,
                "Pulse ID": None,
                "Pulse Name": None,
                "Pulse Description": None,
                "Pulse Creation Date": None,
                "Pulse Modified Date": None
            }])], ignore_index=True)
    
    # Write the dataframe to a CSV file
    df.to_csv(output_file, index=False)
    logging.info(f"Report generated: {output_file}")

if __name__ == "__main__":
    main()
