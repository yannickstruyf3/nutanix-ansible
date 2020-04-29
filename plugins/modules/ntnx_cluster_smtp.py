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
module: ntnx_cluster_smtp
short_description: Allows management of SMTP settings in Nutanix Prism Element clusters.
description:
- Allows management of SMTP settings in Nutanix Prism Element clusters.
author:
    - Yannick Struyf (@yannickstruyf)
version_added: '2.9.5'
requirements:
- python 3
options:
  state:
    description:
    - The state of the SMTP configuration
    required: yes
    default: present
    choices: [ present, absent ]
    type: str
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
  smtp_address:
    description:
    - Hostname or IP of the SMTP server
    required: yes
    type: str
  smtp_port:
    description:
    - Port or IP of the SMTP server
    default: 25
    type: str
  smtp_username:
    description:
    - Username of the SMTP server
    required: yes
    type: str
  smtp_password:
    description:
    - Password of the SMTP server
    required: yes
    type: str
  smtp_secure_mode:
    description:
    - SMTP security mode
    default: NONE
    type: str
    choices: [NONE, STARTTLS, SSL]
  smtp_from_email_address:
    description:
    - E-mailaddress from which notifications should be send
    required: yes
    type: str
  debug:
    description:
    - Enables debug mode. Results in a log file being written to disk
    default: no
    type: bool
"""

EXAMPLES = r"""
- name: "Setting SMTP for clusters"
  ntnx_cluster_smtp:
    state: present
    pe_host: << prism_element_host >>
    pe_username: << prism_element_username >>
    pe_password: << prism_element_password >>
    ssl_verify: False
    smtp_address: << smtp_address >>
    smtp_port: << smtp_port >>
    smtp_username: user@domain.local
    smtp_password: << smtp_password >>
    smtp_secure_mode: NONE
    smtp_from_email_address: no-reply@domain.local
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


class NtnxClusterSmtpManager:
    def __init__(self, logger, module, final_state):
        self.logger = logger
        self.state = module.params["state"]
        self.connection_wrapper = ConnectionWrapper(
            module.params["pe_host"],
            module.params["pe_port"],
            module.params["pe_username"],
            module.params["pe_password"],
            module.params["ssl_verify"],
        )
        self.smtp_address = module.params["smtp_address"]
        self.smtp_port = module.params["smtp_port"]
        self.smtp_username = module.params["smtp_username"]
        self.smtp_password = module.params["smtp_password"]
        self.smtp_secure_mode = module.params["smtp_secure_mode"]
        self.smtp_from_email_address = module.params["smtp_from_email_address"]

        self.request_helper = RequestHelper(
            module, logger, self.connection_wrapper, requires_cookie=False
        )
        self.prism_object_fetcher = PrismObjectFetcher(self.logger, self.request_helper)
        self.final_state = final_state

    def get_smtp(self):
        response_json = self.request_helper.get(
            "/PrismGateway/services/rest/v1/cluster/smtp"
        )
        self.logger.info("get smtp: %s" % str(response_json))
        if not response_json.get("address", None) and not response_json.get(
            "secureMode", None
        ):
            return None
        return response_json

    def create_smtp(self):
        request_json = {
            "address": self.smtp_address,
            "port": self.smtp_port,
            "username": self.smtp_username,
            "password": self.smtp_password,
            "secureMode": self.smtp_secure_mode,
            "fromEmailAddress": self.smtp_from_email_address,
            "emailStatus": None,
        }
        self.logger.info("creating: %s" % json.dumps(request_json))
        response_json = self.request_helper.put(
            "/PrismGateway/services/rest/v1/cluster/smtp", request_json
        )
        self.logger.info("create response: %s" % str(response_json))
        return self.get_smtp()

    def update_smtp(self, smtp):
        self.logger.info("in update")
        if self.__is_desired_state(smtp):
            self.logger.info("was desired state")
            return smtp
        self.logger.info("was not desired state: deleting")
        self.delete_smtp()
        self.logger.info("recreating")
        return self.create_smtp()

    def delete_smtp(self):
        self.logger.info("deleting")
        response_json = self.request_helper.delete(
            "/PrismGateway/services/rest/v1/cluster/smtp"
        )
        self.logger.info("create response: %s" % str(response_json))

    def __is_desired_state(self, smtp):
        if (
            smtp["address"] == self.smtp_address
            and smtp["port"] == self.smtp_port
            and smtp["username"] == self.smtp_username
            and smtp["secureMode"] == self.smtp_secure_mode
            and smtp["fromEmailAddress"] == self.smtp_from_email_address
        ):
            return True
        return False


module = AnsibleModule(
    argument_spec=dict(
        state=dict(default="present", choices=["absent", "present"]),
        pe_host=dict(required=True),
        pe_port=dict(default="9440"),
        pe_username=dict(required=True),
        pe_password=dict(required=True, no_log=True),
        ssl_verify=dict(required=False, type="bool", default=False),
        smtp_address=dict(required=True),
        smtp_port=dict(required=False, default="25"),
        smtp_username=dict(required=True),
        smtp_password=dict(required=True, no_log=True),
        smtp_secure_mode=dict(default="NONE", choices=["NONE", "STARTTLS", "SSL"]),
        smtp_from_email_address=dict(required=True),
        debug=dict(required=False, type="bool", default=False),
    )
)


def main():
    logger = NtnxLogger("ntnx_cluster_smtp", debug_enabled=module.params["debug"])
    final_state = FinalState()
    ntnx_cluster_smtp_manager = NtnxClusterSmtpManager(logger, module, final_state)

    state = ntnx_cluster_smtp_manager.state
    smtp = ntnx_cluster_smtp_manager.get_smtp()

    logger.info("smtp: %s" % json.dumps(smtp))
    logger.info("State: %s" % str(state))
    logger.info("PRE final_state.changed: " + str(final_state.changed))
    if state == "present":
        # Check if cluster exists
        if not smtp:
            smtp = ntnx_cluster_smtp_manager.create_smtp()
            final_state.changed = True
            final_state.state = "present"
        else:
            logger.info("final_state.changed: " + str(final_state.changed))
            final_state.state = "present"
            smtp = ntnx_cluster_smtp_manager.update_smtp(smtp)
    elif state == "absent":
        if not smtp:
            final_state.changed = False
            final_state.state = "absent"
        else:
            ntnx_cluster_smtp_manager.delete_smtp()
            final_state.changed = True
            final_state.state = "absent"
    else:
        module.fail_json(msg="Unexpected state used! State: %s" % state)
    logger.info(final_state.get_final_state())
    module.exit_json(**final_state.get_final_state())


main()
