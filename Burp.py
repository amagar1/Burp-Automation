from elasticsearch import Elasticsearch
import validators
import os
import requests
import json
import time
import argparse
import getpass
import base64
from dotenv import load_dotenv

scan_status = 'running'


def update_vulns(json):
    if 'ES_USER' in os.environ and 'ES_PASS' in os.environ:
        es = Elasticsearch(os.environ['ES_HOST'], http_auth=(os.environ['ES_USER'], os.environ['ES_PASS']))
    else:
        es = Elasticsearch(os.environ['ES_HOST'])

    kbase_api = os.environ['BURP_URL'] + '/knowledge_base/issue_definitions'
    api_response = rest_with_burp(kbase_api, "GET")
    if api_response.status_code == 200:
        issue_defs = api_response.json()

    issue_events = json['issue_events']
    for issue_event in issue_events:
        issue = issue_event['issue']
        burp_vuln = {'web_app': issue['origin']}

        for issue_def in issue_defs:
            if issue_def['name'] == issue['name']:
                burp_vuln['name'] = issue['name']
                burp_vuln['issue_type_id'] = issue_def['issue_type_id']
                burp_vuln['description'] = issue_def['description']
                if 'remediation' in issue_def:
                    burp_vuln['remediation'] = issue_def['remediation']
                else:
                    burp_vuln['remediation'] = "Burp didn't provide any remediation"
                if 'remediation' in issue_def:
                    burp_vuln['references'] = issue_def['references']
                else:
                    burp_vuln['references'] = "Burp didn't provide any references"
                burp_vuln['vulnerability_classifications'] = issue_def['vulnerability_classifications']
                break
        burp_vuln['path'] = issue['path']
        burp_vuln['severity'] = issue['severity']
        burp_vuln['confidence'] = issue['confidence']
        if not issue['evidence']:
            burp_vuln['request_method'] = 'Not Applicable'
            burp_vuln['vuln_request'] = 'Not Applicable'
            burp_vuln['vuln_response'] = 'Not Applicable'
            burp_vuln['date_found'] = 1579251823627
            # time.strftime('%Y-%m-%dT%H:%M:%S.%fZ', time.localtime(/1000.0))
        elif 'composable_evidence' in issue['evidence'][0]:
            vuln_req = issue['evidence'][0]['composable_evidence']['request_response']['request'][0]['data']
            vuln_req_bytes = vuln_req.encode('ascii')
            vuln_req = (base64.b64decode(vuln_req_bytes)).decode('ascii')
            burp_vuln['request_method'] = vuln_req.split(' ')[0]
            burp_vuln['vuln_request'] = vuln_req
            vuln_resp = issue['evidence'][0]['composable_evidence']['request_response']['response'][0]['data']
            vuln_resp_bytes = vuln_resp.encode('ascii')
            burp_vuln['vuln_response'] = (base64.b64decode(vuln_resp_bytes)).decode('ascii')
            request_time = int(issue['evidence'][0]['composable_evidence']['request_response']['request_time'])
            burp_vuln['date_found'] = request_time
            # time.strftime('%Y-%m-%dT%H:%M:%S.%fZ', time.localtime(request_time/1000.0))
        else:
            vuln_req = issue['evidence'][0]['request_response']['request'][0]['data']
            vuln_req_bytes = vuln_req.encode('ascii')
            vuln_req = (base64.b64decode(vuln_req_bytes)).decode('ascii')
            burp_vuln['request_method'] = vuln_req.split(' ')[0]
            burp_vuln['vuln_request'] = vuln_req
            vuln_resp = issue['evidence'][0]['request_response']['response'][0]['data']
            vuln_resp_bytes = vuln_resp.encode('ascii')
            burp_vuln['vuln_response'] = (base64.b64decode(vuln_resp_bytes)).decode('ascii')
            request_time = int(issue['evidence'][0]['request_response']['request_time'])
            burp_vuln['date_found'] = request_time
            # time.strftime('%Y-%m-%dT%H:%M:%S.%fZ', time.localtime(request_time/1000.0))
        es.index(index="burp-vulns", body=burp_vuln)


def rest_with_burp(url, method, data=None):
    headers = {

    }
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers)
        if method == 'POST':
            response = requests.post(url, data=json.dumps(data), headers=headers)
        return response
    except UnicodeEncodeError as e:
        print("Burp API Request returned an error. Error {}".format(e))


def burp_scan(url, username=None, password=None):
    # url = input("Please provide URL for the scan: ")
    if validators.url(url):
        scan_api = os.environ['BURP_URL'] + "/scan"

        if username is not None or password is not None:
            data = {
                "application_logins": [
                    {
                        "password": username,
                        "username": password
                    }
                ],
                "urls": [url]
            }
        else:
            data = {
                "urls": [url]
            }
        api_response = rest_with_burp(scan_api, "POST", data)
        if api_response.status_code == 201:
            print("Burp scan initiated successfully!")
            scan_id = api_response.headers['Location']
            status = 'running'
            while status == 'running':
                check_scan_status(scan_id)


def check_scan_status(scan_id):
    scan_api = os.environ['BURP_URL'] + "/scan/" + scan_id
    response = rest_with_burp(scan_api, "GET")
    if response.status_code == 200:
        status = response.json()["scan_status"]
        if status == "succeeded":
            update_vulns(response.json())
            print("Burp Report uploaded  successfully to ELK")
            os._exit(1)
        else:
            if status == "paused":
                print('The scan has been indefinitely paused due to an error! Exiting..')
                os._exit(-1)
            time.sleep(10)
            return


if __name__ == "__main__":

    load_dotenv()
    burp_parser = argparse.ArgumentParser(description='Burp scan Automation and reporting')
    burp_parser.add_argument('URL', type=str, help='Add URL of the Web Application')
    burp_parser.add_argument('-U', '--USERNAME', type=str, help='Username for Authentication')
    burp_parser.add_argument('-P', '--PASSWORD', action='store_true', dest='password', help='Password')
    args = burp_parser.parse_args()
    if args.password or args.USERNAME:
        if args.USERNAME is None:
            print("Please provide username as well.")
            os._exit(-1)
        password = getpass.getpass('Enter Password:')
        burp_scan(args.URL, args.USERNAME, password)
    burp_scan(args.URL)
