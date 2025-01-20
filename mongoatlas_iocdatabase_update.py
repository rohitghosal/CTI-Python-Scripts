import pymongo
import pandas as pd
import logging
#import dns.resolver
#dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
#dns.resolver.default_resolver.nameservers = ['8.8.8.8']

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def update_database_with_new_iocs(excel_file, sheet_name):
    # Connect to MongoDB
    client = pymongo.MongoClient("mongodb+srv://rghosal008:GhostEmperor2024@cluster0.l0wfdfb.mongodb.net/")
    db = client["ioc_database"]
    collection = db["ioc_collection"]

    # Load the specific Excel sheet
    df = pd.read_excel(excel_file, sheet_name=sheet_name)

    # Loop through each row and check if the IOC exists in the collection
    new_records = []
    for index, row in df.iterrows():
        ioc_value = row['Value']
        release_date = row['Release Date']

        # Check if a record with the same Value and Release Date already exists
        existing_record = collection.find_one({"Value": ioc_value, "Release Date": release_date})

        if not existing_record:
            # If not found, add to new records list
            new_records.append({
                "Release Date": release_date,
                "Indicator Type": row["Indicator Type"],
                "Value": ioc_value,
                "Additional Notes": row["Additional Notes"],
                "Attack Phase": row["Attack Phase"],
                "Payload / Attack / Threat Actor Name/ Type": row["Payload / Attack / Threat Actor Name/ Type"],
                "sheet_name": sheet_name
            })

    # Insert new records into MongoDB
    if new_records:
        collection.insert_many(new_records)
        logging.info(f"Inserted {len(new_records)} new records from sheet '{sheet_name}'.")
    else:
        logging.info(f"No new records found in sheet '{sheet_name}'.")

if __name__ == "__main__":
    update_database_with_new_iocs(r'C:\Users\rghosal008\OneDrive - pwc\Documents\Threat Advisory\IOC LOOKUP\Mongo Atlas\IOC_Database.xlsx', "2024")
