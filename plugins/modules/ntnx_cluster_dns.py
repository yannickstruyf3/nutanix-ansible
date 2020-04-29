#!/usr/bin/python
# Copyright (c) 2020 Yannick Struyf
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: ntnx_cluster_dns
short_description: Allows management of DNS settings in Nutanix Prism Element clusters.
description:
- Allows management of DNS settings in Nutanix Prism Element clusters.
author:
    - Yannick Struyf (@yannickstruyf)
version_added: '2.9.5'
requirements:
- python 3
options:
  pe_host:
    description:
    - Prism Element hostname
    required: yes
    type: str
  pe_port:
    description:
    - Prism Element port
    default: 9440
    type: str
  pe_username:
    description:
    - Prism Element username
    required: yes
    type: str
  pe_password:
    description:
    - Prism Element password
    required: yes
    type: str
  ssl_verify:
    description:
    - Use explicit ssl verification
    default: no
    type: bool
  dns_servers:
    description:
    - List containing the required DNS servers (strings) for Prism Element
    required: yes
    type: list
  debug:
    description:
    - Enables debug mode. Results in a log file being written to disk
    default: no
    type: bool
"""

EXAMPLES = r"""
- name: "Setting DNS for clusters"
  ntnx_cluster_dns:
    pe_host: << prism_element_host >>
    pe_username: << prism_element_username >>
    pe_password: << prism_element_password >>
    ssl_verify: False
    dns_servers:
        - dns_server_1
        - dns_server_2
        - dns_server_3
"""

RETURN = r"""
"""

try:
    import base64
    import json
    import logging
    import os
    import socket
    import time

    import requests
    from ansible.module_utils.basic import AnsibleModule
    from requests.auth import HTTPBasicAuth

    from ansible_collections.yst.ntnx.plugins.module_utils.ntnx_utils import (
        ConnectionWrapper,
        FinalState,
        PrismObjectFetcher,
        RequestHelper,
        NtnxLogger,
    )
except Exception as e:
    raise Exception(f"Failed to perform imports: {e}")


class NtnxClusterDnsManager:
    def __init__(self, logger, module, final_state):
        self.logger = logger
        self.connection_wrapper = ConnectionWrapper(
            module.params["pe_host"],
            module.params["pe_port"],
            module.params["pe_username"],
            module.params["pe_password"],
            module.params["ssl_verify"],
        )

        self.dns_servers = module.params["dns_servers"]
        self.request_helper = RequestHelper(
            module, logger, self.connection_wrapper, requires_cookie=False
        )
        self.prism_object_fetcher = PrismObjectFetcher(self.logger, self.request_helper)
        self.final_state = final_state

    def get_dns(self):
        response_json = self.request_helper.get(
            "/PrismGateway/services/rest/v1/cluster/name_servers"
        )
        self.logger.info(response_json)
        return response_json

    def modify_dns(self):
        self.__check_dns_list()
        current_dns = self.get_dns()
        if current_dns == self.dns_servers:
            self.final_state.changed = False
            return
        self.__remove_dns_servers(current_dns)
        self.__add_dns_servers(self.dns_servers)

    def __add_dns_servers(self, dns_servers):
        if len(dns_servers) == 0:
            self.logger.info("No servers to add")
            return
        response_json = self.request_helper.post(
            "/PrismGateway/services/rest/v1/cluster/name_servers/add_list", dns_servers
        )
        self.logger.info("create response_json: %s" % json.dumps(response_json))
        self.final_state.changed = True

    def __remove_dns_servers(self, dns_servers):
        if len(dns_servers) == 0:
            self.logger.info("No servers to remove")
            return
        response_json = self.request_helper.post(
            "/PrismGateway/services/rest/v1/cluster/name_servers/remove_list",
            dns_servers,
        )
        self.logger.info("create response_json: %s" % json.dumps(response_json))
        self.final_state.changed = True

    def __check_dns_list(self):
        len_list = len(self.dns_servers)
        if len_list == 0:
            module.fail_json(msg="Minimum one DNS server must be passed")
        if len_list > 3:
            module.fail_json(msg="Maximum three DNS servers can be passed")
        for dns in self.dns_servers:
            if not self.__is_ip(dns):
                module.fail_json(msg="Invalid IP found: %s" % dns)

    def __is_ip(self, addr):
        try:
            socket.inet_aton(addr)
            return True
        except socket.error:
            return False


module = AnsibleModule(
    argument_spec=dict(
        pe_host=dict(required=True),
        pe_port=dict(default="9440"),
        pe_username=dict(required=True),
        pe_password=dict(required=True, no_log=True),
        ssl_verify=dict(required=False, type="bool", default=False),
        dns_servers=dict(required=True, type="list"),
        debug=dict(required=False, type="bool", default=False),
    )
)


def main():
    logger = NtnxLogger("ntnx_cluster_dns", debug_enabled=module.params["debug"])
    final_state = FinalState()
    final_state.state = "present"
    ntnx_cluster_dns_manager = NtnxClusterDnsManager(logger, module, final_state)

    ntnx_cluster_dns_manager.modify_dns()
    logger.info(final_state.get_final_state())
    module.exit_json(**final_state.get_final_state())


main()
