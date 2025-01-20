import csv
import pymongo
import re
import time
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def search_keywords_in_mongodb(keywords_file, output_csv):
    # Connect to MongoDB
    client = pymongo.MongoClient("mongodb+srv://rghosal008:GhostEmperor2024@cluster0.l0wfdfb.mongodb.net/")
    db = client["ioc_database"]
    collection = db["ioc_collection"]

    # Load keywords from the file
    with open(keywords_file, 'r') as file:
        keywords = [line.strip() for line in file]

    # Compile regex patterns for each keyword (case-insensitive)
    keyword_patterns = [re.compile(re.escape(keyword), re.IGNORECASE) for keyword in keywords]

    # Open CSV file for writing results
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ["Release Date", "Indicator Type", "Value", "Additional Notes", 
                      "Attack Phase", "Payload / Attack / Threat Actor Name/ Type", "sheet_name"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        total_keywords = len(keywords)
        for i, pattern in enumerate(keyword_patterns):
            # Search in "Payload / Attack / Threat Actor Name/ Type" and "Additional Notes" fields
            query = {
                "$or": [
                    {"Payload / Attack / Threat Actor Name/ Type": {"$regex": pattern}},
                    {"Additional Notes": {"$regex": pattern}}
                ]
            }
            matching_records = collection.find(query)

            found_any = False
            for record in matching_records:
                writer.writerow({
                    "Release Date": record.get("Release Date"),
                    "Indicator Type": record.get("Indicator Type"),
                    "Value": record.get("Value"),
                    "Additional Notes": record.get("Additional Notes"),
                    "Attack Phase": record.get("Attack Phase"),
                    "Payload / Attack / Threat Actor Name/ Type": record.get("Payload / Attack / Threat Actor Name/ Type"),
                    "sheet_name": record.get("sheet_name")
                })
                found_any = True
            
            if found_any:
                logging.info(f"Keyword '{keywords[i]}' found in the database.")
            else:
                logging.info(f"Keyword '{keywords[i]}' not found in the database.")

            # Log progress
            logging.info(f"Processed {i+1}/{total_keywords} keywords.")
    
    logging.info("Search completed. Results have been written to the CSV file.")

if __name__ == "__main__":
    start_time = time.time()
    search_keywords_in_mongodb("keywords.txt", "output2.csv")
    logging.info(f"Total time taken: {time.time() - start_time} seconds")