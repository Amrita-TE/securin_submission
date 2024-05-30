import requests
from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['securin']
collection = db['cve']

# Fetch JSON data from the URL
url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
response = requests.get(url)
data = response.json()

# Parse and update MongoDB
vulnerable_list = data['vulnerabilities']
for vuln_data in vulnerable_list:
    cve_data = vuln_data['cve']
    cve_id = cve_data['id']

    # Check if CVE already exists in MongoDB
    existing_cve = collection.find_one({'id': cve_id})

    if existing_cve:
        # Update existing document
        collection.update_one({'id': cve_id}, {'$set': cve_data})
        print(f"Updated CVE {cve_id}")
    else:
        # Insert new document
        collection.insert_one(cve_data)
        print(f"Inserted new CVE {cve_id}")

print("Task completed.")
