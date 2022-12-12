# -*- coding: utf-8 -*-
#
#  VULNERS OPENSOURCE
#  __________________
#
#  Vulners Project [https://vulners.com]
#  All Rights Reserved.
#
__author__ = "Kir Ermakov <isox@vulners.com>"
import distro

from .oscommands import execute

LOOPBACK = ['127.0.0.1', '0:0:0:0:0:0:0:1']


def get_os_parameters():
    # Gather meta information about the system

    platform_id = distro.id()
    platform_version = distro.version()

    # In most cases this info will be valid, but there is some list of exclusions

    # If it's a Darwin, this is probably Mac OS. We need to get visible version using 'sw_vers' command
    if platform_id.lower() == 'darwin':
        os_params = execute('sw_vers').splitlines()
        platform_id = os_params[0].split(":")[1].strip()
        platform_version = os_params[1].split(":")[1].strip()
        return platform_id, platform_version

    return platform_id, platform_version
