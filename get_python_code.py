import requests
from pymongo import MongoClient

# API endpoint
url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-1010218"

# MongoDB connection details
mongo_client = MongoClient("mongodb://localhost:27017/")
db = mongo_client["securin"]
collection = db["cve"]

# Make the HTTP GET request
response = requests.get(url)

# Check if the request was successful
if response.status_code == 200:
    # Parse the JSON response
    data = response.json()
    
    # Insert data into MongoDB
    if "vulnerabilities" in data:
        cve_items = data["vulnerabilities"]
        for item in cve_items:
            cve = item.get("cve", {})
            
            # Insert the entire CVE data into MongoDB
            collection.insert_one(cve)
            
        print("Data inserted into MongoDB successfully.")
    else:
        print("No vulnerabilities found in the response.")
else:
    print(f"Failed to retrieve data. HTTP Status code: {response.status_code}")
