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
module: ntnx_bucket
short_description: Allows creation, deletion and modification of Nutanix Objects buckets.
description:
- Enables the management of Nutanix Objects buckets through the REST API.
- Allows setting permissions for buckets
version_added: '2.9.5'
author:
    - Yannick Struyf (@yannickstruyf)
requirements:
- python 3
options:
  name:
    description:
    - Name of the bucket to be created, updated or deleted
    required: yes
    type: str
  description:
    description:
    - Description of the bucket to be created, updated or deleted
    required: no
    type: str
  state:
    description:
    - The state of the bucket
    required: yes
    type: str
    default: present
    choices: [ present, absent ]
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
  object_store:
    description:
    - Name of the object store in which the bucket will be created
    required: yes
    type: str
  bucket_permissions:
    description:
    - List permissions assigned to the bucket
    - Assigning the 'regenerate_key' option for a permission object will result in a new secret key to be generated for that user
    suboptions:
        username:
            description: name of the user
            required: yes
            type: str
        permissions:
            description: list of permissions. Can only contain 'read' and/or 'write'
            type: list
            required: yes
        regenerate_key:
            description: boolean to indicated regeneration of new key
            type: bool
            default: no
    default: [ ]
    type: list
  debug:
    description:
    - Enables debug mode. Results in a log file being written to disk
    default: no
    type: bool
"""

EXAMPLES = r"""
- name: "bucket CREATE"
  ntnx_bucket:
    name: << bucket_name >>
    object_store: << object_store_name >>
    state: present
    pc_host: << pc_host >>
    pc_username: << pc_username >>
    pc_password: << pc_password >>
    ssl_verify: False
    bucket_permissions:
        - username: user1@domain.local
          regenerate_key: yes
          permissions:
                - read
                - write
        - username: user2@domain.local
          permissions:
                - read
                - write

- name: "bucket DELETE"
  ntnx_bucket:
    name: "<<bucket_name>>"
    object_store: << object_store >>
    state: absent
    pc_host: << pc_host >>
    pc_username: << pc_username >>
    pc_password: << pc_password >>
    ssl_verify: False
"""

RETURN = r"""
access_keys:
  description: New access keys for the users who had 'regenerate_key' enabled
  returned: success
  type: dict
  sample:
    {
        "user1@domain.local": {
            "access_key": "my_access_key",
            "secret_key": "my_secret_key"
        }
    }
"""

try:
    import json
    import logging
    import time
    import logging
    import time

    from ansible.module_utils.basic import AnsibleModule

    from ansible_collections.yst.ntnx.plugins.module_utils.ntnx_utils import (
        ConnectionWrapper,
        FinalState,
        NtnxLogger,
        RequestHelper,
    )

except Exception as e:
    raise Exception(f"Failed to perform imports: {e}")


class NtnxBucketManager:
    object_store_obj = None
    regenerate_key_list = []

    def __init__(self, logger, module, final_state):
        self.logger = logger
        self.name = module.params["name"]
        self.state = module.params["state"]
        self.connection_wrapper = ConnectionWrapper(
            module.params["pc_host"],
            module.params["pc_port"],
            module.params["pc_username"],
            module.params["pc_password"],
            module.params["ssl_verify"],
        )
        self.wait_completion = module.params["wait_completion"]
        self.request_helper = RequestHelper(module, logger, self.connection_wrapper)
        self.final_state = final_state
        self.object_store = module.params["object_store"]
        self.description = module.params["description"]
        self.bucket_permissions = module.params["bucket_permissions"]

    def create_bucket_obj(self):
        request_json = {
            "api_version": "3.0",
            "metadata": {"kind": "bucket"},
            "spec": {
                "name": self.name,
                "description": self.description,
                "resources": {"features": []},
            },
        }
        self.logger.info("create request_json: %s" % json.dumps(request_json))
        object_store_uuid = self.__get_object_store_uuid(self.__get_object_store())
        response_json = self.request_helper.post(
            "/oss/api/nutanix/v3/objectstores/%s/buckets" % object_store_uuid,
            request_json,
        )
        self.logger.info("create response_json: %s" % json.dumps(response_json))
        return response_json

    def get_bucket_obj(self):
        self.logger.info("getting object store")
        self.object_store_obj = self.__get_object_store()
        self.logger.info("object store: %s" % json.dumps(self.object_store_obj))
        object_store_uuid = self.__get_object_store_uuid(self.object_store_obj)
        response = self.request_helper.get(
            "/oss/api/nutanix/v3/objectstores/%s/buckets/%s"
            % (object_store_uuid, self.name),
            error_on_bad_request=False,
        )
        return response

    def delete_bucket_obj(self, bucket_obj):
        object_store_uuid = self.__get_object_store_uuid(self.__get_object_store())
        response_json = self.request_helper.delete(
            "/oss/api/nutanix/v3/objectstores/%s/buckets/%s"
            % (object_store_uuid, self.name)
        )
        self.logger.info("deleter response: %s " % json.dumps(response_json))

    def set_bucket_permissions(self, bucket_obj):
        self.logger.info("self.bucket_permissions: %s" % str(self.bucket_permissions))
        if not self.bucket_permissions:
            return
        self.__bucket_permission_manager()
        current_bucket_permissions = self.get_current_bucket_permissions(bucket_obj)
        self.logger.info(
            "current_bucket_permissions: "
            + json.dumps(current_bucket_permissions, indent=2)
        )
        self.logger.info(
            "self.bucket_permissions: " + json.dumps(self.bucket_permissions, indent=2)
        )
        if not sorted(
            current_bucket_permissions, key=lambda i: i["username"]
        ) == sorted(self.bucket_permissions, key=lambda i: i["username"]):
            object_store_uuid = self.__get_object_store_uuid(self.__get_object_store())
            request_json = {
                "name": self.name,
                "bucket_permissions": self.bucket_permissions,
            }
            self.logger.info(
                "permissions request_json: %s" % (json.dumps(request_json))
            )
            self.logger.info(
                "objectstore id %s bucket id %s" % (object_store_uuid, self.name)
            )

            response_json = self.request_helper.put(
                "/oss/api/nutanix/v3/objectstores/%s/buckets/%s/share"
                % (object_store_uuid, self.name),
                request_json,
            )
            self.logger.info(
                "permissions response json: %s" % json.dumps(response_json)
            )
            self.final_state.changed = True
        self.__do_key_regeneration()

    def get_current_bucket_permissions(self, bucket_obj):
        permissions_list = []
        object_store_uuid = self.__get_object_store_uuid(self.__get_object_store())
        request_json = {
            "entity_type": "bucket",
            "entity_ids": [self.name],
            "group_member_count": 1,
            "group_member_attributes": [
                {"attribute": "name"},
                {"attribute": "buckets_share"},
            ],
        }
        response_json = self.request_helper.post(
            "/oss/api/nutanix/v3/objectstores/%s/groups" % object_store_uuid,
            request_json,
        )
        if response_json["filtered_entity_count"] != 1:
            module.fail_json(msg="Error when retrieving permissions for bucket!")
        query_data = response_json["group_results"][0]["entity_results"][0]["data"]
        for d in query_data:
            if d.get("name") == "buckets_share":
                if len(d["values"]) == 1 and len(d["values"][0]["values"]) == 1:
                    permissions_list = json.loads(d["values"][0]["values"][0])
                break
        self.logger.info("permissions_list: " + str(permissions_list))
        return_array = []
        for p in permissions_list:
            return_array.append(
                {"username": p["usernames"][0], "permissions": p["permissions"]}
            )
        return return_array

    def __do_key_regeneration(self):
        if not self.regenerate_key_list:
            self.regenerate_key_list = []
        key_regeneration_data = {}
        for r in self.regenerate_key_list:
            self.final_state.changed = True
            request_json = {
                "users": [{"username": r, "type": "external"}],
                "regenerate_key": True,
            }
            response_json = self.request_helper.post(
                "/oss/iam_proxy/buckets_access_keys", request_json
            )
            key_data = response_json["access_keys"][0]
            key_regeneration_data[r] = {
                "access_key": key_data["access_key_id"],
                "secret_key": key_data["secret_access_key"],
            }
        self.final_state.extra["access_keys"] = key_regeneration_data

    def __bucket_permission_manager(self):
        self.logger.info("check ,a[]")
        for bp in self.bucket_permissions:
            self.__check_bucket_permission_structure_helper(bp)

    def __check_bucket_permission_structure_helper(self, permission_obj):
        self.logger.info("In helper")
        fail_msg = "Incorrect permission:"
        allowed_permissions = ["READ", "WRITE"]
        mandatory_keys = ["username", "permissions"]
        # check mandatory keys
        [
            module.fail_json(msg="%s key %s must be set" % (fail_msg, k))
            for k in mandatory_keys
            if not permission_obj.get(k, None)
        ]
        # put everything to uppercase
        if not isinstance(permission_obj.get("permissions", None), list):
            module.fail_json(
                msg="%s value for key permissions must have type array" % (fail_msg)
            )
        permission_obj["permissions"] = list(
            map(lambda e: e.upper(), list(set(permission_obj.get("permissions"))))
        )
        permission_obj["permissions"].sort()
        # check if permission values are correct
        [
            module.fail_json(
                msg="%s permission %s not in %s"
                % (fail_msg, p, str(allowed_permissions))
            )
            for p in permission_obj["permissions"]
            if p not in allowed_permissions
        ]
        regenerate_key = permission_obj.pop("regenerate_key", False)
        if not (isinstance(regenerate_key, bool)):
            module.fail_json(msg="%s regenerate_key must be a boolean" % (fail_msg))
        if regenerate_key:
            self.regenerate_key_list.append(permission_obj["username"])

    def __get_object_store_uuid(self, object_store_obj=None):
        if not object_store_obj:
            object_store_obj = self.__get_object_store()
        return object_store_obj["metadata"]["uuid"]

    def __get_object_store(self):
        if self.object_store_obj:
            return self.object_store_obj
        self.logger.info("PRE GET __get_object_store ")
        response_json = self.request_helper.get("/oss/api/nutanix/v3/objectstores/list")
        self.logger.info("__get_object_store response: %s" % json.dumps(response_json))
        entities = list(
            filter(
                lambda e: e["spec"]["name"] == self.object_store, response_json["specs"]
            )
        )
        self.logger.info("entities: %s" % json.dumps(entities))
        if len(entities) == 0:
            module.fail_json(
                msg="No object store found with name %s. Please verify manually!!"
                % (self.object_store)
            )
        if len(entities) > 1:
            module.fail_json(
                msg="Multiple object stores found with name %s. Please verify manually!!"
                % (self.object_store)
            )
        self.object_store_obj = entities[0]
        return self.object_store_obj

    def __get_bucket_uuid(self, bucket_obj):
        bucket_uuid = bucket_obj.get("metadata", {"uuid": None}).get("uuid")
        if not bucket_uuid:
            module.fail_json(msg="Unable to retrieve bucket uuid")
        return bucket_uuid


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
        object_store=dict(required=True),
        bucket_permissions=dict(required=False, type="list", default=[]),
        debug=dict(required=False, type="bool", default=False),
    )
)


def main():
    logger = NtnxLogger("ntnx_bucket", debug_enabled=module.params["debug"])
    final_state = FinalState()
    ntnx_bucket_manager = NtnxBucketManager(logger, module, final_state)

    state = ntnx_bucket_manager.state
    bucket_obj = ntnx_bucket_manager.get_bucket_obj()

    logger.info("bucket_obj: %s" % json.dumps(bucket_obj))
    logger.info("State: %s" % str(state))
    logger.info("PRE final_state.changed: " + str(final_state.changed))
    if state == "present":
        # Check if cluster exists
        if not bucket_obj:
            bucket_obj = ntnx_bucket_manager.create_bucket_obj()
            final_state.changed = True
            final_state.state = "present"
        else:
            logger.info("final_state.changed: " + str(final_state.changed))
            final_state.state = "present"
        ntnx_bucket_manager.set_bucket_permissions(bucket_obj)
    elif state == "absent":
        if not bucket_obj:
            final_state.changed = False
            final_state.state = "absent"
        else:
            ntnx_bucket_manager.delete_bucket_obj(bucket_obj)
            final_state.changed = True
            final_state.state = "absent"
    else:
        module.fail_json(msg="Unexpected state used! State: %s" % state)
    module.exit_json(**final_state.get_final_state())


main()
