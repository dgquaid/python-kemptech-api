#!/usr/bin/env python

# refresh all the xml files in tests/integration/data/xml.

import os
import sys

import requests

from conf import XML_DATA_DIR, clear_dir

IP = "10.154.190.153"
USER = "bal"
PASS = "2fourall"


def main():
    # clear the xml directory
    clear_dir(XML_DATA_DIR)
    run_access_cmd("addvs", {'vs': '10.154.1.10', 'port': '80', 'prot': 'tcp'})
    run_access_cmd("modvs", {'vs': '10.154.1.10', 'port': '80', 'prot': 'tcp', 'forcel7': '1'})
    run_access_cmd("addrs", {'vs': '10.154.1.10', 'port': '80', 'prot': 'tcp', 'rs': '10.154.1.11', 'rsport': '8080'})
    run_access_cmd("modrs", {'vs': '10.154.1.10', 'port': '80', 'prot': 'tcp', 'rs': '10.154.1.11', 'rsport': '8080', 'weight': '950'})
    run_access_cmd("showrs", {'vs': '10.154.1.10', 'port': '80', 'prot': 'tcp', 'rs': '10.154.1.11', 'rsport': '8080'})
    run_access_cmd("showvs", {'vs': '10.154.1.10', 'port': '80', 'prot': 'tcp'})
    run_access_cmd("listvs")
    run_access_cmd("delrs", {'vs': '10.154.1.10', 'port': '80', 'prot': 'tcp', 'rs': '10.154.1.11', 'rsport': '8080'})
    run_access_cmd("delvs", {'vs': '10.154.1.10', 'port': '80', 'prot': 'tcp'})
    run_access_cmd("set", {'param': 'syslogcritical', 'value': '1.1.1.1'})
    run_access_cmd("get", {'param': 'syslogcritical'})
    run_access_cmd("stats")


def run_access_cmd(cmd, params=None):
    endpoint = "https://{ip}/access/{cmd}?".format(ip=IP, cmd=cmd)
    try:
        resp = requests.get(endpoint, auth=(USER, PASS), verify=False, params=params)
    except requests.exceptions.RequestException:
        print("An error happened generating the XML file for the command {}".format(cmd))
        sys.exit(1)
    with open(os.path.join(XML_DATA_DIR, "{}.xml".format(cmd)), mode='w') as output_file:
        output_file.write(resp.text)


if __name__ == '__main__':
    main()

