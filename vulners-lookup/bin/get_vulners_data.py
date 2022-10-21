import os
import sys
import json
import csv
from requests import post
import logging, logging.handlers

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import dispatch, EventingCommand, Configuration, Option, validators
from splunk.clilib import cli_common as cli
import splunk

@Configuration()
class GetVulnersDataCommand(EventingCommand):
    
    """
    Custom command arguments
    """
    osname_field = Option(require=True, validate=validators.Fieldname())
    osversion_field = Option(require=True, validate=validators.Fieldname()) 
    package_field = Option(require=True, validate=validators.Fieldname())
    hosts_field = Option(require=True, validate=validators.Fieldname())
    show_description = Option(require=False, validate=validators.Boolean(), default=False)
    only_vulnerable_packages = Option(require=False, validate=validators.Boolean(), default=True)
    disable_exploits_search = Option(require=False, validate=validators.Boolean(), default=False)

    token_name = 'vulners_api_token'
    token_realm = 'vulners_api_token_realm'

    cfg = cli.getConfStanza('vulners','setup')
    vulners_endpoint = cfg.get('vulners_endpoint')
    exploits_search_chunk_size = int(cfg.get('exploits_batch_size'))

    VULNERS_LINKS = {
        'pkgChecker': vulners_endpoint+'/api/v3/audit/audit/',
        'cveChecker': vulners_endpoint+'/api/v3/search/id/',
        'exploitChecker': vulners_endpoint+'/api/v3/search/lucene/'
    }

    DEFAULT_HEADERS = {
        'User-agent': 'Vulners-Splunk-scan/0.0.5',
        'Content-type': 'application/json'
    }
    
    SPLUNK_HOME = os.environ['SPLUNK_HOME']
        
    def setup_logging(self):
        """
        Basic python logger settings from https://dev.splunk.com/enterprise/docs/developapps/addsupport/logging/loggingsplunkextensions
        """
        logger = logging.getLogger('splunk.vulnersLookup')   
        LOGGING_DEFAULT_CONFIG_FILE = os.path.join(self.SPLUNK_HOME, 'etc', 'log.cfg')
        LOGGING_LOCAL_CONFIG_FILE = os.path.join(self.SPLUNK_HOME, 'etc', 'log-local.cfg')
        LOGGING_STANZA_NAME = 'python'
        LOGGING_FILE_NAME = "vulnersLookup.log"
        BASE_LOG_PATH = os.path.join('var', 'log', 'splunk')
        LOGGING_FORMAT = "%(asctime)s %(levelname)-s\t%(module)s:%(lineno)d - %(message)s"
        splunk_log_handler = logging.handlers.RotatingFileHandler(os.path.join(self.SPLUNK_HOME, BASE_LOG_PATH, LOGGING_FILE_NAME), mode='a') 
        splunk_log_handler.setFormatter(logging.Formatter(LOGGING_FORMAT))
        logger.addHandler(splunk_log_handler)
        splunk.setupSplunkLogger(logger, LOGGING_DEFAULT_CONFIG_FILE, LOGGING_LOCAL_CONFIG_FILE, LOGGING_STANZA_NAME)
        return logger

    def get_encrypted_api_token(self, search_command):
        """
        Get Vulners API token from Splunk storage/passwords API endpoint
        """
        secrets = search_command.service.storage_passwords
        return next(secret for secret in secrets if (secret.realm == self.token_realm and secret.username == self.token_name)).clear_password
    
    def get_audit_info(self, osname='', osversion='', packages=tuple(), token='', logger=logging.Logger):
        """
        Get OS name, its version and a list of installed packages and perform the actual request to Vulners API.
        """
        
        result = dict()
        all_cve = list()
        
        payload = {
            'os': osname,
            'version': osversion,
            'package': packages,
            'apiKey': token
        }
        try:
            resp = post(self.VULNERS_LINKS.get('pkgChecker'), headers=self.DEFAULT_HEADERS, data=json.dumps(payload))
        except Exception as e:
            message = "Problems with connection to Vulners API (" + self.VULNERS_LINKS.get('pkgChecker') + ")."
            self.exceptions_handler(e, message, logger)
        
        if resp.status_code == 200 and resp.json().get('result') == "OK":
            for pkg, info in resp.json()['data'].get('packages', {}).items():
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
            return {}

    def get_cve_info(self, cve_list=[], token='', logger=logging.Logger):
        """
        Get CVE details based on aggregated CVE list from Vulners API
        """
        
        cve_info = dict()
        payload = {
            'id': cve_list,
            'apiKey': token
        }

        try:
            resp = post(self.VULNERS_LINKS.get('cveChecker'), headers=self.DEFAULT_HEADERS, data=json.dumps(payload))
        except Exception as e:
            message = "Problems with connection to Vulners API (" + self.VULNERS_LINKS.get('cveChecker') + ")."
            self.exceptions_handler(e, message, logger)
            
        if resp.status_code == 200 and resp.json().get('result') == "OK":
            for cve, info in resp.json()['data'].get('documents', {}).items():
                if len(info['cvss3']) != 0:
                    scoreCVSS = info.get('cvss3', {}).get('cvssV3',{}).get('baseScore')
                    severityText = info.get('cvss3', {}).get('cvssV3',{}).get('baseSeverity')
                    vectorCVSS = info.get('cvss3', {}).get('cvssV3',{}).get('vectorString')
                else:
                    scoreCVSS = info.get('cvss2', {}).get('cvssV2',{}).get('baseScore')
                    severityText = info.get('cvss2', {}).get('severity')
                    vectorCVSS = info.get('cvss2', {}).get('cvssV2',{}).get('vectorString')
                vulnersScore = info.get('enchantments', {}).get('vulnersScore')
                cve_info[cve] = {
                    "scoreCVSS": scoreCVSS,
                    "vulnersScore": vulnersScore,
                    "severityText": severityText,
                    "vectorCVSS": vectorCVSS
                }
                if self.show_description:
                    description = info.get('description')
                    cve_info[cve]['description'] = description
            return cve_info
        else:
            return {}

    def get_exploit_info(self, cve_list=[], token='', logger=logging.Logger):
        """
        Get public available exploits based on CVE data from Vulners API with lucene search.
        """

        result = dict()
        exploitSearchString = ""

        for item in cve_list:
            if len(exploitSearchString) == 0:
                exploitSearchString += item
            else:
                exploitSearchString += ' OR ' + item
        
        payload = {
            'query': "bulletinFamily:exploit AND cvelist:(" + exploitSearchString + ")",
            'fields': [
                "title", 
                "href", 
                "sourceHref", 
                "cvelist", 
                "sourceData"],
            'skip': 0,
            'size': 10000,
            'apiKey': token
        }

        try:
            resp = post(self.VULNERS_LINKS.get('exploitChecker'), headers=self.DEFAULT_HEADERS, data=json.dumps(payload))
        except Exception as e:
            message = "Problems with connection to Vulners API (" + self.VULNERS_LINKS.get('exploitChecker') + ")."
            self.exceptions_handler(e, message, logger)
        
        if resp.status_code == 200 and resp.json().get('result') == "OK":
            ress = resp.json().get('data')
            if (len(resp.json().get('data').get('search')) != 0):
                for cve in cve_list:
                    result[cve] = []
                    for item in resp.json().get('data').get('search'):
                        if cve in item['_source']['cvelist']:
                            exploit = {
                                'exploit_link': item['_source']['href']
                            }
                            result[cve].append(exploit)
                for cve in list(result):
                    if len(result[cve]) == 0:
                        result.pop(cve)
                return result
            else:
                return {}
        else:
            return {}
        
    def csv_normalization(self, result=dict()):
        """
        Service method for normilizing lists for CSV lookup file
        """
        
        result_csv = dict()
        for key, value in result.items():
            if isinstance(value, list):
                list2str = ""
                list2str = ' '.join(map(str, value))
                result_csv[key] = list2str
            else:
                result_csv[key] = result[key]
        return result_csv
    
    def exceptions_handler(self, e=Exception, message=str, logger=logging.Logger):
        """
        Service method for handling exceptions, self.write_error will envoke method for printing custom message in Splunk Web Interface
        """
        logger.error(message + " (" + str(e) + ")")
        self.write_error(message + " Look for details in vulnersLookup.log")
        exit()

    def transform(self, records):
        
        logger = self.setup_logging()

        osnamefield = self.osname_field
        osversionfield = self.osversion_field
        packagefield = self.package_field
        hostsfield = self.hosts_field
        vulnfield = 'vulnId'
        scorefield = 'scoreCVSS'
        vectorfield = 'vectorCVSS'
        vulners_scorefield = 'vulnersScore'
        severityfield = 'severityText'
        exploitsfield = 'possibleExploits'
        descriptionfield = 'descriptionText'

        try:
            token = self.get_encrypted_api_token(self)
        except Exception as e:
            message = "Problems with getting Vulners API Token from Splunk Password Storage. Check the initialization (setup) status of the application."
            self.exceptions_handler(e, message, logger)
    
        exploits_search_chunk_size = self.exploits_search_chunk_size

        LOG_FILENAME = os.path.join(self.SPLUNK_HOME, 'var', 'log', 'vulners-lookup', 'VulnersLookup.log')
        LOG_DIRNAME = os.path.dirname(LOG_FILENAME)
        if not os.path.exists(LOG_DIRNAME):
            os.makedirs(LOG_DIRNAME)

        VULNERS_CSV = os.path.join(self.SPLUNK_HOME, 'etc', 'apps', 'vulners-lookup', 'lookups', 'vulners.csv')
        LOOKUP_DIRNAME = os.path.dirname(VULNERS_CSV)
        if not os.path.exists(LOOKUP_DIRNAME):
            os.makedirs(LOOKUP_DIRNAME)

        csv_lookup_outfile = open(VULNERS_CSV, 'w')
        csv_header = [ hostsfield, osnamefield, osversionfield, packagefield, vulnfield, scorefield, vulners_scorefield, severityfield, vectorfield ]
        if self.show_description:
            csv_header.append(descriptionfield)
        if not self.disable_exploits_search:
            csv_header.append(exploitsfield)
        w = csv.DictWriter(csv_lookup_outfile, fieldnames=csv_header, delimiter=',', quotechar='"')
        w.writeheader()

        os_version_packages = dict()
        
        """
        Loop for creating aggregated dictionary of software packages based on operating system name and version 
        """
        for request in records:
            osname, osversion, package, hosts = request[osnamefield], request[osversionfield], request[packagefield], request[hostsfield]
            if osname not in os_version_packages:
                os_version_packages[osname] = dict()
            if osversion not in os_version_packages[osname]:
                os_version_packages[osname][osversion] = {packagefield: {}}
            if package not in os_version_packages[osname][osversion][packagefield]:
                os_version_packages[osname][osversion][packagefield][package] = {'hosts': []}
            if isinstance(hosts, list):
                for host in hosts:
                    if host not in os_version_packages[osname][osversion][packagefield][package]['hosts']:
                        os_version_packages[osname][osversion][packagefield][package]['hosts'].append(host)
            else:
                os_version_packages[osname][osversion][packagefield][package]['hosts'].append(hosts)
        
        all_cve = list()

        for osname, os_details in os_version_packages.items():
            for osversion, package_info in os_details.items():
                packages = [key for key in package_info[packagefield]]
                os_version_packages[osname][osversion]['res'] = dict()
                res = self.get_audit_info(osname, osversion, packages, token, logger)
                if not len(res) == 0:
                    all_cve += res.get('all_cve', [])
                    res.pop('all_cve')
                    os_version_packages[osname][osversion]['res'] = res

        all_unique_cve = list()
        for item in all_cve:
            if item not in all_unique_cve:
                all_unique_cve.append(item)
                
        cve_info = self.get_cve_info(all_unique_cve, token)

        exploit_info = dict()
        if not self.disable_exploits_search:
            if len(all_unique_cve) > exploits_search_chunk_size:
                chunked_cve = list()
                for slice in range(0, len(all_unique_cve), exploits_search_chunk_size):
                    chunked_cve = all_unique_cve[slice:slice+exploits_search_chunk_size]
                    chunked_res = self.get_exploit_info(chunked_cve, token, logger)
                    if not len(chunked_res) == 0:
                        exploit_info.update(chunked_res)
            else:
                exploit_info = self.get_exploit_info(all_unique_cve, token)
                
        for osname, os_details in os_version_packages.items():
            for osversion, package_info in os_details.items():
                packages = package_info[packagefield]

                if not self.only_vulnerable_packages:
                    for pkg_name, pkg_hosts in packages.items():
                        if pkg_name not in os_version_packages[osname][osversion]['res']:
                            result = {
                                osnamefield: osname,
                                osversionfield: osversion,
                                packagefield: pkg_name,
                                hostsfield: pkg_hosts['hosts'],
                                vulnfield: "",
                                scorefield: "",
                                vulners_scorefield: "",
                                severityfield: "",
                                vectorfield: ""
                            }
                            if self.show_description:
                                result[descriptionfield] = ""
                            if not self.disable_exploits_search:
                                result[exploitsfield] = ""
                            yield result

                            w.writerow(self.csv_normalization(result))

                for pkg_res_name, pkg_res_data in os_version_packages[osname][osversion]['res'].items():
                    cvelist = pkg_res_data.get("cve", [])
                    for cve in cvelist:
                        result = {
                            osnamefield: osname,
                            osversionfield: osversion,
                            packagefield: pkg_res_name,
                            hostsfield: packages[pkg_res_name]['hosts']
                        }
                        result[vulnfield] = cve
                        result[scorefield] = cve_info[cve].get('scoreCVSS')
                        result[vulners_scorefield] = cve_info[cve].get('vulnersScore')
                        result[severityfield] = cve_info[cve].get('severityText')
                        result[vectorfield] = cve_info[cve].get('vectorCVSS')
                        if self.show_description:
                            result[descriptionfield] = cve_info[cve].get('description')
                        if not self.disable_exploits_search:
                            if cve in exploit_info:
                                exploits = list()
                                for item in exploit_info[cve]:
                                    exploits.append(item['exploit_link'])
                                result[exploitsfield] = exploits
                            else:
                                result[exploitsfield] = ""
                        yield result
      
                        w.writerow(self.csv_normalization(result))

        csv_lookup_outfile.close()

dispatch(GetVulnersDataCommand, sys.argv, sys.stdin, sys.stdout, __name__)