# Author: elliotwellick

import argparse
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def check_vulns(url):
    """
    Checks for known vulnerabilities in a specified URL.
    Returns a list of vulnerabilities found.
    """
    vulns = []

    payload = "' or 1=1 --"
    resp = requests.get(url + "/search?q=" + payload, verify=False)
    if "Error executing query" in resp.text:
        vulns.append("SQL injection")

    payload = "<script>alert('XSS')</script>"
    resp = requests.post(url + "/comment", data={"text": payload}, verify=False)
    if payload in resp.text:
        vulns.append("XSS")

    payload = "../../../../etc/passwd"
    resp = requests.get(url + "/page?file=" + payload, verify=False)
    if "root:" in resp.text:
        vulns.append("File inclusion")

    return vulns

parser = argparse.ArgumentParser(description='Check for vulnerabilities in a URL.')
parser.add_argument('url', type=str, help='The URL to test for vulnerabilities')

args = parser.parse_args()

url = args.url

vulns = check_vulns(url)
if vulns:
    print(f"The following vulnerabilities were found (Author: github.com/elliotwellick):")
    for vuln in vulns:
        print("- " + vuln)
else:
    print("No vulnerabilities found")
