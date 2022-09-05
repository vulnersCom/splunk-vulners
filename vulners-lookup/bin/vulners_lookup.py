import os
import sys
import csv
import json
import logging 

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "lib"))
from requests import get, post
from splunk.clilib import cli_common as cli
import splunklib.client as client

"""Lookup script that utilizes the Vulners API to check for vulnerabilities of the found packages.

In fact it simply performs a single request like Vulners Agent does with a list of installed packages for every input host.
The results are then saved into a local lookup csv file for further use in dashboarding.
"""

cfg = cli.getConfStanza('vulners','setup')

vulners_endpoint = cfg.get('endpoint')

VULNERS_LINKS = {
    'pkgChecker': vulners_endpoint+'/api/v3/audit/audit/',
    'cveChecker': vulners_endpoint+'/api/v3/search/id/'
}

#service = client.connect(...)
#storage_passwords = service.storage_passwords

#for passwd in storage_passwords:  # type: StoragePassword
#    if (passwd.realm is None or passwd.realm.strip() == "") and passwd.username == "virustotal":
#                API_KEY = passwd.clear_password

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

DEFAULT_HEADERS = {
    'User-agent': 'Vulners-Splunk-scan/0.0.5',
    'Content-type': 'application/json'
}


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
            'apiKey': cfg.get('token', '')
        }
        try:
            res = post(VULNERS_LINKS.get('pkgChecker'), headers=DEFAULT_HEADERS, data=json.dumps(payload))
        except Exception as e:
            log(e)
            return {}
        log(res.text)
        if res.status_code == 200 and res.json().get('result') == "OK":
            result = dict()
            all_cve = list()
            for pkg, info in res.json()['data'].get('packages', {}).items():
                cvelist = []
                for vuln_name, desc in info.items():
                    cvelist.append(sum(map(lambda x: x.get("cvelist", []), desc), []))
                cvelist = list(set(sum(cvelist, [])))
                if len(cvelist):
                    result[pkg] = {"cve": cvelist}
                    all_cve += cvelist
            result['all_cve'] = all_cve
            return result
        else:
            log("[vulners_lookup] Error contacting the vulners server")
            log(res.text)
            return {}


def get_cve_info(cve_list=[]):
    cve_info = dict()
    payload = {
        'id': cve_list,
        'apiKey': cfg.get('token', '')
    }
    try:
        res = post(VULNERS_LINKS.get('cveChecker'), headers=DEFAULT_HEADERS, data=json.dumps(payload))
    except Exception as e:
        log(e)
    log(res.text)
    if res.status_code == 200 and res.json().get('result') == "OK":
        res = res.json()
        for cve, info in res['data'].get('documents', {}).items():
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
    header = reader.fieldnames

    w = csv.DictWriter(outfile, fieldnames=header)
    w2 = csv.DictWriter(v_outfile, fieldnames=header)
    w.writeheader()
    w2.writeheader()

    hosts = dict()
    os_version_packages = dict()
    for request in reader:
        hostname, osname, osversion, package = request[hostfield], request[osfield], request[osversionfield], request[packagefield]
        if hostname not in hosts:
            hosts[hostname] = {osfield: osname, osversionfield: osversion, packagefield: []}
        hosts[hostname][packagefield].append(package)
        if osname not in os_version_packages:
            os_version_packages[osname] = dict()
        if osversion not in os_version_packages[osname]:
            os_version_packages[osname][osversion] = {packagefield: []}
        if package not in os_version_packages[osname][osversion][packagefield]:
            os_version_packages[osname][osversion][packagefield].append(package)

    all_cve = list()

    for osname, os_details in os_version_packages.items():
       for osversion, package_info in os_details.items():
           packages = package_info[packagefield]
           res = lookup(osname, osversion, packages)
           all_cve += res.get('all_cve', [])
           res.pop('all_cve')
           os_version_packages[osname][osversion]['res'] = res

    for hostname, host_info in hosts.items():
        osname = host_info[osfield]
        osversion = host_info[osversionfield]
        packages = host_info[packagefield]
        log("Host %s with "%hostname + str(packages))

    cve_info = get_cve_info(all_cve)
    for hostname, host_info in hosts.items():
        osname = host_info[osfield]
        osversion = host_info[osversionfield]
        for pkg in host_info[packagefield]:
            for pkg_res_name,pkg_res_data in os_version_packages[osname][osversion]['res'].items():
                if pkg == pkg_res_name:
                    result = {
                        hostfield: hostname,
                        osfield: osname,
                        osversionfield: osversion,
                        packagefield: pkg
                    }
                    cvelist = pkg_res_data.get("cve", [])
                    for cve in cvelist:
                        result[vulnfield] = cve
                        result[scorefield] = cve_info[cve].get('score')
                        result[v_scorefield] = cve_info[cve].get('vulnersScore')
                        result[titlefield] = cve_info[cve].get('title')
                        result[severityfield] = cve_info[cve].get('severityText')
                        w.writerow(result)
                        w2.writerow(result)

    v_outfile.close()


try:
    main()
except Exception as e:
    log(e)
