import pandas as pd
from pymongo import MongoClient
from tqdm import tqdm  # For progress logging

# Connect to MongoDB (ensure consistent database naming)
client = MongoClient('mongodb+srv://rghosal008:GhostEmperor2024@cluster0.l0wfdfb.mongodb.net/')
db = client['ioc_database']  # Keep the database name in lowercase
collection = db['ioc_collection']  # Keep the collection name in lowercase

# Load Excel data into MongoDB with progress logging
def load_excel_to_mongodb(excel_file):
    xl = pd.ExcelFile(excel_file)
    
    for sheet_name in xl.sheet_names:
        print(f"Processing sheet: {sheet_name}")
        df = xl.parse(sheet_name, header=0)  # Use the first row as the header
        
        # Drop rows and columns that are entirely NaN
        df.dropna(how='all', axis=1, inplace=True)  # Drop columns with all NaN values
        df.dropna(how='all', axis=0, inplace=True)  # Drop rows with all NaN values
        
        # Ensure all column names are strings
        df.columns = df.columns.map(str)
        
        # Add a field for the sheet name
        df['sheet_name'] = sheet_name
        
        # Convert DataFrame to a list of dictionaries
        data = df.to_dict(orient='records')
        
        # Insert data with progress logging
        try:
            for record in tqdm(data, desc=f"Inserting records from sheet {sheet_name}"):
                collection.insert_one(record)  # Insert each record individually
        except Exception as e:
            print(f"Error inserting data from sheet {sheet_name}: {e}")
    
    print("Data loading into MongoDB completed.")

# Path to the Excel file
excel_file = r'C:\Users\rghosal008\Documents\Threat Advisory\IOC LOOKUP\Mongo Atlas\IOC_Database.xlsx'
load_excel_to_mongodb(excel_file)