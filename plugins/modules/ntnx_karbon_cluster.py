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
module: ntnx_karbon_cluster
short_description: Allows creation, deletion and modification of Nutanix Karbon clusters.
description:
- Enables the management of Nutanix Karbon clusters through the REST API.
- Allows scaling of Nutanix Karbon clusters
author:
    - Yannick Struyf (@yannickstruyf)
version_added: '2.9.5'
requirements:
- python 3
- Nutanix Karbon 2.0
options:
  name:
    description:
    - Name of the Karbon cluster to be created, updated or deleted
    required: yes
    type: str
  description:
    description:
    - Description of the Karbon cluster to be created, updated or deleted
    required: no
    type: str
  state:
    description:
    - The state of the Karbon cluster
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
  wait_completion:
    description:
    - Wait for the task to be completed
    default: yes
    type: bool
  nutanix_cluster:
    description:
    - Name of the Nutanix cluster on which the Nutanix Karbon cluster will be provisioned
    - Required when not(state=present).
    required: no
    type: str
  nutanix_cluster_username:
    description:
    - Username of the target Nutanix cluster (Prism Element)
    - Required when not(state=present).
    required: no
    type: str
  nutanix_cluster_password:
    description:
    - Password of the target Nutanix cluster (Prism Element)
    - Required when not(state=present).
    required: no
    type: str
  nutanix_network:
    description:
    - Name of the Nutanix Karbon network
    - Required when not(state=present).
    required: no
    type: str
  karbon_image:
    description:
    - Name of the Nutanix Karbon image
    - Required when not(state=present).
    required: no
    type: str
  os_flavor:
    description:
    - Flavor of the Nutanix Karbon image
    default: centos7.5.1804
    type: str
  karbon_version:
    description:
    - Version of the Nutanix Karbon image
    - Required when not(state=present).
    required: no
    type: str
  nutanix_storage_container:
    description:
    - Target storage container for the Nutanix Karbon cluster
    - Required when not(state=present).
    required: no
    type: str
  karbon_service_cluster_ip_range:
    description:
    - Service network CIDR for the Nutanix Karbon cluster
    default: 172.19.0.0/16
    type: str
  karbon_network_cidr:
    description:
    - Pod network CIDR for the Nutanix Karbon cluster
    default: 172.20.0.0/16
    type: str
  karbon_network_subnet_len:
    description:
    - network subnet size for the Nutanix Karbon cluster
    default: 24
    type: int
  worker_count:
    description:
    - Amount of workers in the Nutanix Karbon cluster
    default: 1
    type: int
  worker_cpu:
    description:
    - Amount of CPU for workers in the Nutanix Karbon cluster
    default: 8
    type: int
  worker_memory_mib:
    description:
    - Amount of memory for workers in the Nutanix Karbon cluster
    default: 8192
    type: int
  worker_disk_mib:
    description:
    - Amount of memory for workers in the Nutanix Karbon cluster
    default: 122880
    type: int
  master_cpu:
    description:
    - Amount of CPU for masters in the Nutanix Karbon cluster
    default: 2
    type: int
  master_memory_mib:
    description:
    - Amount of memory for masters in the Nutanix Karbon cluster
    default: 4096
    type: int
  master_disk_mib:
    description:
    - Amount of memory for masters in the Nutanix Karbon cluster
    default: 122880
    type: int
  etcd_cpu:
    description:
    - Amount of CPU for etcds in the Nutanix Karbon cluster
    default: 4
    type: int
  etcd_memory_mib:
    description:
    - Amount of memory for etcds in the Nutanix Karbon cluster
    default: 8192
    type: int
  etcd_disk_mib:
    description:
    - Amount of memory for etcds in the Nutanix Karbon cluster
    default: 40960
    type: int
  debug:
    description:
    - Enables debug mode. Results in a log file being written to disk
    default: no
    type: bool
"""

EXAMPLES = r"""
- name: Karbon CREATE cluster
  ntnx_karbon_cluster:
    name: << cluster_name >>
    state: present
    pc_host: << pc_host >>
    pc_username: << pc_username >>
    pc_password: << pc_password >>
    ssl_verify: False
    nutanix_cluster_username: << prism_element_username >>
    nutanix_cluster_password: << prism_element_password >>
    nutanix_cluster: << nutanix_cluster >>
    nutanix_network: << nutanix_network >>
    nutanix_storage_container: << nutanix_storage_container >>
    karbon_image: "karbon-ntnx-0.2"
    karbon_version: "1.14.10-0"
    worker_count: 2
- name: Karbon DELETE Cluster
  ntnx_karbon_cluster:
    name: << cluster_name >>
    state: absent
    pc_host: << pc_host >>
    pc_username: << pc_username >>
    pc_password: << pc_password >>
    ssl_verify: False
"""

RETURN = r"""
worker_ips:
    description: List of provisioned workers IP-addresses
    returned: success
    type: list
    sample:
        - 10.10.10.10
        - 10.10.10.11
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
        name=dict(required=True),
        description=dict(required=False, type="str", default=""),
        state=dict(default="present", choices=["absent", "present"]),
        pc_host=dict(required=True),
        pc_port=dict(default="9440"),
        pc_username=dict(required=True),
        pc_password=dict(required=True, no_log=True),
        ssl_verify=dict(required=False, type="bool", default=False),
        wait_completion=dict(required=False, type="bool", default=True),
        nutanix_cluster=dict(required=False, type="str"),
        nutanix_cluster_username=dict(required=False, type="str"),
        nutanix_cluster_password=dict(required=False, no_log=True, type="str"),
        nutanix_network=dict(required=False, type="str"),
        karbon_image=dict(required=False, type="str"),
        os_flavor=dict(required=False, type="str", default="centos7.5.1804"),
        karbon_version=dict(required=False, type="str"),
        nutanix_storage_container=dict(required=False, type="str"),
        karbon_service_cluster_ip_range=dict(
            required=False, type="str", default="172.19.0.0/16"
        ),
        karbon_network_cidr=dict(required=False, type="str", default="172.20.0.0/16"),
        karbon_network_subnet_len=dict(required=False, type="int", default=24),
        worker_count=dict(required=False, type="int", default=1),
        worker_cpu=dict(required=False, type="int", default=8),
        worker_memory_mib=dict(required=False, type="int", default=8192),
        worker_disk_mib=dict(required=False, type="int", default=122880),
        master_cpu=dict(required=False, type="int", default=2),
        master_memory_mib=dict(required=False, type="int", default=4096),
        master_disk_mib=dict(required=False, type="int", default=122880),
        etcd_cpu=dict(required=False, type="int", default=4),
        etcd_memory_mib=dict(required=False, type="int", default=8192),
        etcd_disk_mib=dict(required=False, type="int", default=40960),
        debug=dict(required=False, type="bool", default=False),
    ),
    required_if=[
        [
            "state",
            "present",
            [
                "nutanix_cluster",
                "nutanix_network",
                "karbon_image",
                "karbon_version",
                "nutanix_storage_container",
                "nutanix_cluster_password",
                "nutanix_cluster_username",
            ],
        ],
    ],
)


def main():
    logger = NtnxLogger("ntnx_karbon_cluster", debug_enabled=module.params["debug"])
    final_state = FinalState()
    ntnx_cluster_manager = NtnxKarbonClusterManager(logger, module, final_state)

    state = ntnx_cluster_manager.state
    cluster_obj = ntnx_cluster_manager.get_cluster_obj()

    logger.info("cluster_obj: %s" % json.dumps(cluster_obj))
    logger.info("State: %s" % str(state))
    logger.info("PRE final_state.changed: " + str(final_state.changed))
    if state == "present":
        # Check if cluster exists
        if not cluster_obj:
            cluster_obj = ntnx_cluster_manager.create_cluster_obj()
            final_state.changed = True
            final_state.state = "present"
        else:
            logger.info("final_state.changed: " + str(final_state.changed))
            final_state.state = "present"
            cluster_obj = ntnx_cluster_manager.update_cluster_obj(cluster_obj)
        final_state.extra["worker_ips"] = ntnx_cluster_manager.get_worker_ips(
            cluster_obj
        )

    elif state == "absent":
        if not cluster_obj:
            final_state.changed = False
            final_state.state = "absent"
        else:
            ntnx_cluster_manager.delete_cluster_obj(cluster_obj)
            final_state.changed = True
            final_state.state = "absent"
    else:
        module.fail_json(msg="Unexpected state used! State: %s" % state)
    logger.info(final_state.get_final_state())
    module.exit_json(**final_state.get_final_state())


main()
