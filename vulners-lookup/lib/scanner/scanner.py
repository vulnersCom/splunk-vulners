# -*- coding: utf-8 -*-
#
#  VULNERS OPENSOURCE
#  __________________
#
#  Vulners Project [https://vulners.com]
#  All Rights Reserved.
#
__author__ = "Kir Ermakov <isox@vulners.com>"

import json
import os
import logging

from .common import osdetect, oscommands


class Scanner(object):


    linux_package_commands = {

        'rpm':{
            'packages': """rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n'""",
        },

        'deb':{
            'packages': """dpkg-query -W -f='${Status} ${Package} ${Version} ${Architecture}\\n'|awk '($1 == "install") && ($2 == "ok") {print $4" "$5" "$6}'""",
        },

    }

    def __init__(self, log_level="DEBUG", log_path=None):
        PROJECT_ROOT_PATH = os.path.dirname(__file__)
        file_path = os.path.join(PROJECT_ROOT_PATH, 'config', 'supported.json')
        with open(file_path) as ifile:
            self.supported_os = json.load(ifile)

        self.log = logging.getLogger(self.__class__.__name__)
        self.log.propagate = False
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.log.setLevel(log_level)
        if log_path:
            if  not os.path.isdir(log_path):
                os.makedirs(log_path)
            file_handler = logging.FileHandler(os.path.join(log_path, "%s.log" % self.__class__.__name__))
            file_handler.setFormatter(formatter)
            self.log.addHandler(file_handler)

    def linux_scan(self, os_name, os_version, os_data):

        package_list = oscommands.execute(self.linux_package_commands[os_data['packager']]['packages']).splitlines()

        active_kernel = oscommands.execute("uname -r")

        pkg_str = os_name + ',' + os_version + ',%s'
        packages = [pkg_str % package for package in package_list if not (package.startswith("kernel-") and package!= "kernel-%s" % active_kernel)]

        return packages

    # TODO[gmedian]: uncomment returns when in production
    def run(self):
        os_name, os_version = osdetect.get_os_parameters()
        self.log.debug("OS Detection complete: %s %s" % (os_name, os_version))

        supported_os_lib = self.supported_os['supported']

        # Exit if OS is not supported in any way
        if os_name not in supported_os_lib:
            self.log.error("Can't perform scan request: Unknown OS %s. Supported os list: %s" % (os_name, supported_os_lib))
            return

        os_data = supported_os_lib.get(os_name, supported_os_lib.get('debian', None))

        if not hasattr(self, "%s_scan" % os_data['osType']) or not callable(getattr(self, "%s_scan" % os_data['osType'], None)):
            self.log.error("Can't scan this type of os: %s - no suitable scan method found" % os_data['osType'])
            return

        scan_result = getattr(self, "%s_scan" % os_data['osType'])(
                                                                    os_name = os_name,
                                                                    os_version = os_version,
                                                                    os_data=os_data
                                                                  )
        self.log.debug("Scan complete: %s" % scan_result)

        if scan_result:
            print('\n'.join(scan_result))

