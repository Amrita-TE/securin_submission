from flask import Flask, render_template, request
from pymongo import MongoClient

app = Flask(__name__)

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['securin']
cve_collection = db['cve']

@app.route('/cves/list')
def list_cves():
    # Get query parameters
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    sort_field = request.args.get('sort', 'publishedDate')
    sort_order = int(request.args.get('order', 1))

    # Calculate the offset and limit
    offset = (page - 1) * per_page

    # Retrieve sorted CVE documents from MongoDB
    cves = list(cve_collection.find().sort(sort_field, sort_order).skip(offset).limit(per_page))
    total_records = cve_collection.count_documents({})

    return render_template('list.html', cves=cves, total_records=total_records, page=page, per_page=per_page, sort=sort_field, order=sort_order)

@app.route('/cves/<cveID>')
def view_cve(cveID):
    cve = cve_collection.find_one({'id': cveID})
    if cve:
        return render_template('detail.html', cve=cve)
    else:
        return "CVE not found", 404

if __name__ == '__main__':
    app.run(debug=True)
