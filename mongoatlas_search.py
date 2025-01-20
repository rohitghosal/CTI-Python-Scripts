import re
import csv
from pymongo import MongoClient
from tqdm import tqdm

# MongoDB connection setup
client = MongoClient('mongodb+srv://rghosal008:GhostEmperor2024@cluster0.l0wfdfb.mongodb.net/')
db = client['ioc_database']
collection = db['ioc_collection']

# Function to defang IOCs
def defang_ioc(ioc):
    ioc = ioc.replace('http://', 'hxxp://')
    ioc = ioc.replace('.', '[.]')
    return ioc

# Function to load IOCs from the query file
def load_iocs(query_file):
    with open(query_file, 'r') as f:
        iocs = f.read().splitlines()
    return [defang_ioc(ioc) if not re.search(r'\[\.\]', ioc) else ioc for ioc in iocs]

# Function to search IOCs in MongoDB and write to CSV
def search_iocs_in_mongodb(iocs, output_csv):
    results = []
    for ioc in tqdm(iocs, desc="Searching IOCs"):
        # Search in the MongoDB collection using the "Value" field
        matching_records = collection.find({"Value": ioc})
        for record in matching_records:
            results.append(record)
            print(f"\nFound match for IOC: {ioc}")
        else:
            print(f"\nIOC not found in database: {ioc}")

    # Write results to a CSV file
    if results:
        keys = results[0].keys()
        with open(output_csv, 'w', newline='', encoding='utf-8') as output_file:
            dict_writer = csv.DictWriter(output_file, fieldnames=keys)
            dict_writer.writeheader()
            dict_writer.writerows(results)
        print(f"Results written to {output_csv}")
    else:
        print("\nNo matches found.")

# File paths
query_file = 'Q2.txt'
output_csv = 'found_iocs.csv'

# Load IOCs from query file
iocs = load_iocs(query_file)

# Search IOCs in MongoDB and write results to CSV
search_iocs_in_mongodb(iocs, output_csv)
