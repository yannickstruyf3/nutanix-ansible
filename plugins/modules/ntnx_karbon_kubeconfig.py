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
module: ntnx_karbon_kubeconfig
short_description: Gets the kubeconfig file for a Nutanix Karbon cluster.
description:
- Retrieves the kubeconfig file of a  Nutanix Karbon cluster through the REST API.
author:
    - Yannick Struyf (@yannickstruyf)
version_added: '2.9.5'
requirements:
- python 3
- Nutanix Karbon 2.0
options:
  name:
    description:
    - Name of the target Karbon cluster
    required: yes
    type: str
  state:
    description:
    - The state of the kubeconfig file
    required: yes
    default: present
    choices: [ present, absent ]
    type: str
  pc_host:
    description:
    - Prism Central hostname
    required: yes
    type: str
  pc_port:
    description:
    - Prism Central port
    default: 9440
    type: str
  pc_username:
    description:
    - Prism Central username
    required: yes
    type: str
  pc_password:
    description:
    - Prism Central password
    required: yes
    type: str
  ssl_verify:
    description:
    - Use explicit ssl verification
    default: no
    type: bool
  kubeconfig_download_path:
    description:
    - Target path of the kubeconfig file
    default: ./config
    type: str
  debug:
    description:
    - Enables debug mode. Results in a log file being written to disk
    default: no
    type: bool
"""

EXAMPLES = r"""
- name: Karbon GET kubeconfig
  ntnx_karbon_kubeconfig:
    name: << cluster_name >>
    state: present
    pc_host: << pc_host >>
    pc_username: << pc_username >>
    pc_password: << pc_password >>
    kubeconfig_download_path: "./{{ cluster_name }}-kubeconfig"
    ssl_verify: False

- name: Karbon DELETE kubeconfig
  ntnx_karbon_kubeconfig:
    name: << cluster_name >>
    state: absent
    pc_host: << pc_host >>
    pc_username: << pc_username >>
    pc_password: << pc_password >>
    kubeconfig_download_path: "./{{ cluster_name }}-kubeconfig"
    ssl_verify: False
"""

RETURN = r"""
msg:
    description: Command to export the kubeconfig file in PATH
    returned: success
    type: str
    sample: export KUBECONFIG='config'
kubeconfig_path:
    description: Full path of the kubeconfig file
    returned: success
    type: str
    sample: '/tmp/config'
"""
try:
    import base64
    import json
    import os
    import time

    import requests
    from ansible.module_utils.basic import AnsibleModule

    from ansible_collections.yst.ntnx.plugins.module_utils.ntnx_karbon_utils import (
        NtnxKarbonClusterManager,
    )
    from ansible_collections.yst.ntnx.plugins.module_utils.ntnx_utils import (
        FinalState,
        NtnxLogger,
    )
except Exception as e:
    raise Exception(f"Failed to perform imports: {e}")


module = AnsibleModule(
    argument_spec=dict(
        debug=dict(required=False, type="bool", default=False),
        name=dict(required=True),
        state=dict(default="present", choices=["absent", "present"]),
        pc_host=dict(required=True),
        pc_port=dict(default="9440"),
        pc_username=dict(required=True),
        pc_password=dict(required=True, no_log=True),
        ssl_verify=dict(required=False, type="bool", default=False),
        kubeconfig_download_path=dict(default="./config"),
    ),
)


def main():
    logger = NtnxLogger("ntnx_karbon_kubeconfig", debug_enabled=module.params["debug"])
    final_state = FinalState()
    module.params["kubeconfig_download"] = True
    ntnx_cluster_manager = NtnxKarbonClusterManager(logger, module, final_state)
    state = ntnx_cluster_manager.state

    if state == "present":
        cluster_obj = ntnx_cluster_manager.get_cluster_obj()
        if not cluster_obj:
            module.fail_json(msg="Karbon cluster does not exist!")
        else:
            ntnx_cluster_manager.get_kubeconfig_file(cluster_obj)
            final_state.state = "present"
            final_state.changed = True

    elif state == "absent":
        ntnx_cluster_manager.delete_kubeconfig_file()
        final_state.state = "absent"
    else:
        module.fail_json(msg="Unexpected state used! State: %s" % state)
    logger.info(final_state.get_final_state())
    module.exit_json(**final_state.get_final_state())


main()
