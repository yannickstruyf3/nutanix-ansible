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
module: ntnx_cluster_ntp
short_description: Allows management of NTP settings in Nutanix Prism Element clusters.
description:
- Allows management of NTP settings in Nutanix Prism Element clusters.
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
  ntp_servers:
    description:
    - List containing the required NTP servers (strings) for Prism Element
    required: yes
    type: list
  debug:
    description:
    - Enables debug mode. Results in a log file being written to disk
    default: no
    type: bool
"""

EXAMPLES = r"""
- name: "Setting NTP for clusters"
  ntnx_cluster_ntp:
    pe_host: << prism_element_host >>
    pe_username: << prism_element_username >>
    pe_password: << prism_element_password >>
    ssl_verify: False
    ntp_servers:
        - ntp_server_1
        - ntp_server_2
        - ntp_server_3
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


class NtnxClusterNtpManager:
    def __init__(self, logger, module, final_state):
        self.logger = logger
        self.connection_wrapper = ConnectionWrapper(
            module.params["pe_host"],
            module.params["pe_port"],
            module.params["pe_username"],
            module.params["pe_password"],
            module.params["ssl_verify"],
        )

        self.ntp_servers = module.params["ntp_servers"]
        self.request_helper = RequestHelper(
            module, logger, self.connection_wrapper, requires_cookie=False
        )
        self.prism_object_fetcher = PrismObjectFetcher(self.logger, self.request_helper)
        self.final_state = final_state

    def get_ntp(self):
        response_json = self.request_helper.get(
            "/PrismGateway/services/rest/v1/cluster/ntp_servers"
        )
        self.logger.info("get ntp: %s" % str(response_json))
        return response_json

    def modify_ntp(self):
        self.__check_ntp_list()
        current_ntp = self.get_ntp()
        if current_ntp == self.ntp_servers:
            self.final_state.changed = False
            return

        self.__remove_ntp_servers(current_ntp)
        self.__add_ntp_servers(self.ntp_servers)

    def __add_ntp_servers(self, ntp_servers):
        if len(ntp_servers) == 0:
            self.logger.info("No servers to add")
            return
        response_json = self.request_helper.post(
            "/PrismGateway/services/rest/v1/cluster/ntp_servers/add_list", ntp_servers
        )
        self.logger.info("create response_json: %s" % json.dumps(response_json))
        self.final_state.changed = True

    def __remove_ntp_servers(self, ntp_servers):
        if len(ntp_servers) == 0:
            self.logger.info("No servers to remove")
            return
        response_json = self.request_helper.post(
            "/PrismGateway/services/rest/v1/cluster/ntp_servers/remove_list",
            ntp_servers,
        )
        self.logger.info("create response_json: %s" % json.dumps(response_json))
        self.final_state.changed = True

    def __check_ntp_list(self):
        len_list = len(self.ntp_servers)
        if len_list == 0:
            module.fail_json(msg="Minimum one NTP server must be passed")


module = AnsibleModule(
    argument_spec=dict(
        pe_host=dict(required=True),
        pe_port=dict(default="9440"),
        pe_username=dict(required=True),
        pe_password=dict(required=True, no_log=True),
        ssl_verify=dict(required=False, type="bool", default=False),
        ntp_servers=dict(required=True, type="list"),
        debug=dict(required=False, type="bool", default=False),
    )
)


def main():
    logger = NtnxLogger("ntnx_cluster_ntp", debug_enabled=module.params["debug"])
    final_state = FinalState()
    final_state.state = "present"
    ntnx_cluster_ntp_manager = NtnxClusterNtpManager(logger, module, final_state)

    ntnx_cluster_ntp_manager.modify_ntp()
    logger.info(final_state.get_final_state())
    module.exit_json(**final_state.get_final_state())


main()
