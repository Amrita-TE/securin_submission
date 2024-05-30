import unittest
from unittest.mock import patch, MagicMock
from flask import Flask, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from app import app  # Assuming your app code is in a file named `app.py`

class TestCVEAPI(unittest.TestCase):

    @patch('app.MongoClient')
    def setUp(self, mock_mongo_client):
        self.app = app.test_client()
        self.app.testing = True

        # Mock the database and collection
        self.mock_db = MagicMock()
        self.mock_collection = MagicMock()
        mock_mongo_client.return_value = self.mock_db
        self.mock_db.__getitem__.return_value = self.mock_collection

    @patch('app.cve_collection')
    def test_get_all_cves_success(self, mock_cve_collection):
        # Mock the return value of find() method
        mock_cve_collection.find.return_value = [
            {
                "_id": {"$oid": "66577a4f2ec8a451a98ab339"},
                "id": "CVE-2000-0388",
                "sourceIdentifier": "cve@mitre.org",
                "published": "1990-05-09T04:00:00.000",
                "lastModified": "2008-09-10T19:04:33.930",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Buffer overflow in FreeBSD libmytinfo library allows local users to execute commands via a long TERMCAP environmental variable."
                    }
                ],
                "metrics": {
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                                "accessVector": "NETWORK",
                                "accessComplexity": "LOW",
                                "authentication": "NONE",
                                "confidentialityImpact": "PARTIAL",
                                "integrityImpact": "PARTIAL",
                                "availabilityImpact": "PARTIAL",
                                "baseScore": 7.5
                            },
                            "baseSeverity": "HIGH",
                            "exploitabilityScore": 10,
                            "impactScore": 6.4,
                            "acInsufInfo": False,
                            "obtainAllPrivilege": False,
                            "obtainUserPrivilege": True,
                            "obtainOtherPrivilege": False,
                            "userInteractionRequired": False
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "NVD-CWE-Other"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:freebsd:freebsd:3.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "EE38C50A-81FE-412E-9717-3672FAE6A6F4"
                                    },
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:freebsd:freebsd:3.1:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "263F3734-7076-4EA8-B4C0-F37CFC4E979E"
                                    },
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:freebsd:freebsd:3.2:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "0419DD66-FF66-48BC-AD3B-F6AFD0551E36"
                                    },
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:freebsd:freebsd:3.3:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "C3518628-08E5-4AD7-AAF6-A4E38F1CDE2C"
                                    },
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:freebsd:freebsd:3.4:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "B982342C-1981-4C55-8044-AFE4D87623DF"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "ftp://ftp.freebsd.org/pub/FreeBSD/CERT/advisories/FreeBSD-SA-00%3A17.libmytinfo.asc",
                        "source": "cve@mitre.org"
                    },
                    {
                        "url": "http://www.securityfocus.com/bid/1185",
                        "source": "cve@mitre.org"
                    }
                ]
            }
        ]

        response = self.app.get('/api/cves')
        data = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['id'], 'CVE-2000-0388')
        self.assertEqual(data[0]['descriptions'][0]['value'], "Buffer overflow in FreeBSD libmytinfo library allows local users to execute commands via a long TERMCAP environmental variable.")

    @patch('app.cve_collection')
    def test_get_all_cves_failure(self, mock_cve_collection):
        # Simulate an exception when calling find()
        mock_cve_collection.find.side_effect = Exception('Database error')

        response = self.app.get('/api/cves')
        data = response.get_json()

        self.assertEqual(response.status_code, 500)
        self.assertIn('error', data)
        self.assertEqual(data['error'], 'Database error')

if __name__ == '__main__':
    unittest.main()
