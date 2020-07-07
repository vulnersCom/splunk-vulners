from requests import get, post
from splunk.clilib import cli_common as cli

import os
import sys
import csv
import json
import logging 

"""Lookup script that utilizes the Vulners API to check for vulnerabilities of the found packages.

In fact it simply performs a single request like Vulners Agent does with a list of installed packages for every input host.
The results are then saved into a local lookup csv file for further use in dashboarding.
"""

VULNERS_LINKS = {
    'pkgChecker': 'https://vulners.com/api/v3/audit/audit/',
    'cveChecker': 'https://vulners.com/api/v3/search/id/'
}

cfg = cli.getConfStanza('vulners', 'setupentity')

SPLUNK_HOME = os.environ['SPLUNK_HOME']

LOG_FILENAME = os.path.join(SPLUNK_HOME, 'var', 'log', 'vulners-lookup', 'VulnersLookup.log')
LOG_DIRNAME = os.path.dirname(LOG_FILENAME)
if not os.path.exists(LOG_DIRNAME):
    os.makedirs(LOG_DIRNAME)

VULNERS_CSV = os.path.join(SPLUNK_HOME, 'etc', 'apps', 'vulners-lookup', 'lookups', 'vulners.csv')
LOOKUP_DIRNAME = os.path.dirname(VULNERS_CSV)
if not os.path.exists(LOOKUP_DIRNAME):
    os.makedirs(LOOKUP_DIRNAME)

LOG_FORMAT = "[%(asctime)s] %(name)s %(levelname)s: %(message)s"
logging.basicConfig(filename=LOG_FILENAME,level=logging.DEBUG,format=LOG_FORMAT)
loggerrrer = logging.getLogger('VulnersLookup')

def log(s=""):
    loggerrrer.debug(s)
    
def lookup(osname='', osversion='', packages=tuple()):
        """
        Get OS name, its version and a list of installed packages and perform the actual request to Vulners API.
        """

        payload = {
            'os': osname,
            'version': osversion,
            'package': packages,
            'apiKey': cfg.get('vulners_api_key', '')
        }
        headers = {'user-agent': 'Splunk-scan/0.0.1', 'Content-type': 'application/json'}
        try:
            res = post(VULNERS_LINKS.get('pkgChecker'), headers=headers, data=json.dumps(payload))
        except Exception as e:
            log(e)
            return {}
        log(res.text)
        if res.status_code == 200 and res.json().get('result') == "OK":
            result = dict()
            all_cve = list()
            for pkg, info in res.json()['data'].get('packages', {}).items():
                cvelist = []
                fix = []
                for vuln_name, desc in info.items():
                    cvelist.append(sum(map(lambda x: x.get("cvelist", []), desc), []))
                    fix.append(list(map(lambda x: x.get("fix", ""), desc)))
                cvelist = sum(cvelist, [])
                fix = list(set(sum(fix, [])))
                if len(cvelist) or len(fix):
                    result[pkg] = {"cve": cvelist, "fix": fix}
                    all_cve += cvelist
            result['all_cve'] = all_cve
            return result
        else:
            log("[vulners_lookup] Error contacting the vulners server")
            log(res.text)
            return {}

def get_cve_info(cve_list=[]):
    cve_info = dict()
    payload = {'id': cve_list}
    headers = {'user-agent': 'Splunk-scan/0.0.2', 'Content-type': 'application/json'}
    try:
        res = post(VULNERS_LINKS.get('cveChecker'), headers=headers, data=json.dumps(payload))
    except Exception as e:
        log(e)
    log(res.text)
    if res.status_code == 200 and res.json().get('result') == "OK":
        for cve, info in res.json()['data'].get('documents', {}).items():
            score = info.get('cvss', {}).get('score')
            vulnersScore = info.get('enchantments', {}).get('vulnersScore')
            title = info.get('title')
            severity = info.get('cvss2', {}).get('severity')
            cve_info[cve] = {
                "score": score,
                "vulnersScore": vulnersScore,
                "title": title,
                "severityText": severity
            }
        return cve_info

def main():
    if len(sys.argv) != 5:
        log("Usage: python3 vulners_lookup.py [hostname field] [osname field] [osversion field] [package field]")
        sys.exit(1)

    hostfield = sys.argv[1]
    osfield = sys.argv[2]
    osversionfield = sys.argv[3]
    packagefield = sys.argv[4]
    vulnfield = 'vulnId'
    scorefield = 'score'
    v_scorefield = 'vulnersScore'
    titlefield =  'title'
    severityfield = 'severityText'

    infile = sys.stdin
    outfile = sys.stdout
    v_outfile = open(VULNERS_CSV, 'w')


    reader = csv.DictReader(infile)
    header = reader.fieldnames + [vulnfield, scorefield, v_scorefield, titlefield, severityfield]

    w = csv.DictWriter(outfile, fieldnames=header)
    w2 = csv.DictWriter(v_outfile, fieldnames=header)
    w.writeheader()
    w2.writeheader()

    hosts = dict()
    for request in reader:
        hostname, osname, osversion, package = request[hostfield], request[osfield], request[osversionfield], request[packagefield]
        if hostname not in hosts:
            hosts[hostname] = {osfield: osname, osversionfield: osversion, packagefield: []}
        hosts[hostname][packagefield].append(request[packagefield])

    all_cve = list()
    for hostname, host_info in hosts.items():
        osname = host_info[osfield]
        osversion = host_info[osversionfield]
        packages = host_info[packagefield]
        log("Host %s with "%hostname + str(packages))
        res = lookup(osname, osversion, packages)
        host_info['res'] = res
        all_cve += res.get('all_cve', [])
        res.pop('all_cve')

    cve_info = get_cve_info(all_cve)
    for hostname, host_info in hosts.items():
        osname = host_info[osfield]
        osversion = host_info[osversionfield]
        pkg_res = host_info['res']
        for pkg, info in pkg_res.items():
            result = {
                hostfield: hostname,
                osfield: osname,
                osversionfield: osversion,
                packagefield: pkg
            }
            cvelist = info.get("cve", [])
            for cve in cvelist:
                result[vulnfield] = cve
                result[scorefield] = cve_info[cve].get('score')
                result[v_scorefield] = cve_info[cve].get('vulnersScore')
                result[titlefield] = cve_info[cve].get('title')
                result[severityfield] = cve_info[cve].get('severityText')
                w.writerow(result)
                w2.writerow(result)

    v_outfile.close()

main()
