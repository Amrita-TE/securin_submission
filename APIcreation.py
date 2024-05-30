from flask import Flask, jsonify
from flask_cors import CORS
from pymongo import MongoClient

app = Flask(__name__)
CORS(app)  # This will enable CORS for all routes

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['securin']
cve_collection = db['cve']

# API endpoint to get all CVE details
@app.route('/api/cves', methods=['GET'])
def get_all_cves():
    try:
        # Retrieve all CVE documents from MongoDB
        all_cves = list(cve_collection.find())
        return jsonify(all_cves), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
