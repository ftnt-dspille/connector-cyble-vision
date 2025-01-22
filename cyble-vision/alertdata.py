import json


class Alertdata:
    def __init__(self):
        self.dict = {"companyUuid": "65842219-1aea-4aa2-8bb2-ceee36b7a6e6", "orderBy": [{"created_at": "desc"}],
                     "select": {"alert_group_id": "true", "archive_date": "true", "archived": "true",
                                "assignee_id": "true", "assignment_date": "true", "created_at": "true",
                                "data_id": "true", "deleted_at": "true", "description": "true", "hash": "true",
                                "id": "true", "metadata": "true", "risk_score": "true", "service": "true",
                                "severity": "true", "status": "true", "tags": "true", "updated_at": "true",
                                "user_severity": "true"}, "skip": 0, "take": 1,
                     "where": {"created_at": {"gte": "2024-09-04T00:00:00+00:00", "lte": "2024-09-25T00:00:00+00:00"},
                               "service": {"in": ["darkweb_data_breaches"]},
                               "severity": {"in": ["HIGH", "MEDIUM", "LOW"]}, "status": {
                             "in": ["VIEWED", "UNREVIEWED", "CONFIRMED_INCIDENT", "UNDER_REVIEW", "INFORMATIONAL"]}}}
        self.dict2 = {
            "Data Breaches": "darkweb_data_breaches",
            "Ransomware Forum Mentions": "darkweb_ransomware",
            "Compromised Endpoints": "stealer_logs",
            "I2P Links": "i2p",
            "Tor Links": "tor_links",
            "Cybercrime Forum Mentions": "cyber_crime_forums",
            "Darkweb Marketplaces": "darkweb_marketplaces",
            "Telegram Mentions": "telegram_mentions",
            "Discord Mentions": "discord",
            "Compromised Cards": "compromised_cards",
            "Product Vulnerability": "product_vulnerability",
            "Code Analysis - Github": "github",
            "Code Analysis - Bitbucket": "bit_bucket",
            "Cloud Storage": "cloud_storage",
            "File Hashes": "file_hashes",
            "Domain Expiry": "domain_expiry",
            "Subdomains": "subdomains",
            "Assets": "assets",
            "New Port": "new_port",
            "New Vulnerability - CVE": "new_vulnerability",
            "IP Risk Score": "ip_risk_score",
            "Asset SSL Expiry": "ssl_expiry",
            "SPF Monitoring": "spf_monitoring",
            "DNS Zone Monitoring": "dns_zone_monitoring",
            "DMARC Monitoring": "dmarc_monitoring",
            "BIMI Monitoring": "bimi_monitoring",
            "DKIM Monitoring": "dkim_monitoring",
            "Mobile Apps": "mobile_apps",
            "OSINT": "osint",
            "Suspicious Domains": "suspicious_domains",
            "Phishing Monitoring": "phishing",
            "Takedown": "take_down",
            "Social Media Monitoring": "social_media_monitoring",
            "Defacement URL": "defacement_url",
            "Defacement Content": "defacement_content",
            "Defacement Keyword": "defacement_keyword",
            "IoCs": "iocs",
            "Botnet": "botnet",
            "Cyble Research Labs Advisory": "advisory",
            "Cyble Research Labs": "cyble_research_labs",
            "News Flash": "flash_report"
        }

    def get_value(self, key):
        return self.dict.get(key)

    def set_value(self, key, value):
        self.dict[key] = value

    def set_value_in_dict(self, key1, key2, value):
        self.dict[key1][key2] = value

    def update_dictionary(self, new_dict):
        self.set_value("companyUuid", new_dict['companyID'])
        self.set_value("take", new_dict['limit'])
        self.set_value("orderBy", [{"created_at": new_dict['sortBy']}])
        self.set_value_in_dict("where", "status", {"in": new_dict['status']})
        service = self.dict2[new_dict['service']]
        self.set_value_in_dict("where", "service", {"in": [service]})
        self.set_value_in_dict("where", "severity", {"in": new_dict['severity']})
        self.set_value_in_dict("where", "created_at", {"gte": new_dict['begin'], "lte": new_dict['end']})

    def get_dictionary(self):
        return self.dict

    def prepare_post_data(self):
        # Convert the dictionary to a JSON string
        json_data = json.dumps(self.dict)
        # Replace the string ""true"" with "true" (without quotes) for JSON representation
        json_data = json_data.replace('"true"', 'true')
        dict_obj = json.loads(json_data)
        return dict_obj
