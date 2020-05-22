from requests import get, post
from splunk.clilib import cli_common as cli

import os
import sys
import csv
import json
import logging 

"""Lookup script that utilizes the Vulners API to check for vulnerabilities of the found packages.

In fact it simply performs a single request like Vulners Agent does with a list of installed packages.
"""

VULNERS_LINKS = {'pkgChecker':'https://vulners.com/api/v3/audit/audit/'}

cfg = cli.getConfStanza('vulners', 'setupentity')

SPLUNK_HOME = os.environ['SPLUNK_HOME']

LOG_FILENAME = os.path.join(SPLUNK_HOME, 'var', 'log', 'vulners-lookup', 'VulnersLookup.log')
LOG_DIRNAME = os.path.dirname(LOG_FILENAME)
if not os.path.exists(LOG_DIRNAME):
    os.makedirs(LOG_DIRNAME)
LOG_FORMAT = "[%(asctime)s] %(name)s %(levelname)s: %(message)s"
logging.basicConfig(filename=LOG_FILENAME,level=logging.DEBUG,format=LOG_FORMAT)
loggerrrer = logging.getLogger('VulnersLookup')

def log(s=""):
    loggerrrer.debug(s)
    
def lookup(os='ubuntu', version='16.04', packages=('libjpeg-turbo8 1.4.2-0ubuntu3 amd64',)):
        """
        Get OS name, its versin and a list of installed packages and perform the actual request to Vulners API.
        """

        payload = {'os': os,
                   'version': version,
                   'package': packages,
                   'apiKey': cfg.get('vulners_api_key', '') 
        }
        headers = {'user-agent': 'Splunk-scan/0.0.1', 'Content-type': 'application/json'}
        try:
            res = post(VULNERS_LINKS.get('pkgChecker'), headers=headers, data=json.dumps(payload))
        except Exception as e:
            log(e)
        log(res.text)
        if res.status_code == 200 and res.json().get('result') == "OK":
            result = dict()
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
            return result
        else:
            log("[vulners_lookup] Error contacting the vulners server")
            log(res.text)
            return {}

def main():
    if len(sys.argv) != 4:
        log("Usage: python vulners_lookup.py [os field] [version field] [package field]")
        sys.exit(1)

    osfield = sys.argv[1]
    versionfield = sys.argv[2]
    packagefield = sys.argv[3]
    cvefield = 'cve'
    linkfield = 'link'
    fixfield =  'fix'

    infile = sys.stdin
    outfile = sys.stdout

    reader = csv.DictReader(infile)
    header = reader.fieldnames

    w = csv.DictWriter(outfile, fieldnames=reader.fieldnames+[cvefield, fixfield, linkfield])
    w.writeheader()

    os, version = '', ''
    packages = list()
    for request in reader:
        os, version, package = request[osfield], request[versionfield], request[packagefield]
        packages.append(request[packagefield])
    log(packages)
    res = lookup(os, version, packages)
    for pkg, info in res.items():
        result = {
            osfield: os,
            versionfield: version,
            packagefield: pkg
        }
        cvelist = info.get("cve", [])
        cvel = '\n'.join(("https://vulners.com/cve/"+cve for cve in cvelist))
        result[cvefield] = cvel
        fixlist = '\n'.join(info.get("fix", []))
        result[fixfield] = fixlist
        result[linkfield] = "https://vulners.com/"
        w.writerow(result)

main()
