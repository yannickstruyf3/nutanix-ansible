from __future__ import absolute_import, division, print_function

__metaclass__ = type

try:
    import base64
    import json
    import logging
    import os
    import time

    import requests
    from ansible.module_utils.basic import AnsibleModule
    from requests.auth import HTTPBasicAuth

    from ansible_collections.yst.ntnx.plugins.module_utils.ntnx_utils import (
        ConnectionWrapper,
        NtnxFileHandler,
        PrismObjectFetcher,
        RequestHelper,
    )
except Exception as e:
    raise Exception(f"Failed to import: {e}")


class NtnxKarbonClusterManager:
    def __init__(self, logger, module, final_state):
        self.logger = logger
        self.module = module
        self.name = module.params.get("name")
        self.state = module.params.get("state")
        self.connection_wrapper = ConnectionWrapper(
            module.params.get("pc_host"),
            module.params.get("pc_port"),
            module.params.get("pc_username"),
            module.params.get("pc_password"),
            module.params.get("ssl_verify"),
        )
        self.request_helper = RequestHelper(
            module, logger, self.connection_wrapper, requires_cookie=True
        )
        self.kubeconfig_download = module.params.get("kubeconfig_download")
        self.kubeconfig_download_path = module.params.get("kubeconfig_download_path")
        self.ssh_certificates_download = module.params.get("ssh_certificates_download")
        self.ssh_certificates_download_path = module.params.get(
            "ssh_certificates_download_path"
        )
        self.wait_completion = module.params.get("wait_completion")
        self.prism_object_fetcher = PrismObjectFetcher(self.logger, self.request_helper)
        self.final_state = final_state

        self.nutanix_cluster_username = module.params.get("nutanix_cluster_username")
        self.nutanix_cluster_password = module.params.get("nutanix_cluster_password")
        self.nutanix_cluster = module.params.get("nutanix_cluster")
        self.nutanix_network = module.params.get("nutanix_network")
        self.karbon_image = module.params.get("karbon_image")
        self.os_flavor = module.params.get("os_flavor")

        self.description = module.params.get("description")
        self.karbon_service_cluster_ip_range = module.params.get(
            "karbon_service_cluster_ip_range"
        )
        self.karbon_network_cidr = module.params.get("karbon_network_cidr")
        self.karbon_network_subnet_len = module.params.get("karbon_network_subnet_len")
        self.karbon_version = module.params.get("karbon_version")
        self.nutanix_storage_container = module.params.get("nutanix_storage_container")

        self.worker_count = module.params.get("worker_count")
        self.worker_cpu = module.params.get("worker_cpu")
        self.worker_memory_mib = module.params.get("worker_memory_mib")
        self.worker_disk_mib = module.params.get("worker_disk_mib")

        self.master_cpu = module.params.get("master_cpu")
        self.master_memory_mib = module.params.get("master_memory_mib")
        self.master_disk_mib = module.params.get("master_disk_mib")

        self.etcd_cpu = module.params.get("etcd_cpu")
        self.etcd_memory_mib = module.params.get("etcd_memory_mib")
        self.etcd_disk_mib = module.params.get("etcd_disk_mib")

    def create_cluster_obj(self):
        self.__validate_worker_count()
        self.nutanix_cluster_uuid = self.prism_object_fetcher.find_metadata_for_object(
            "clusters", self.nutanix_cluster, error_on_not_found=True
        )["uuid"]
        self.nutanix_network_uuid = self.prism_object_fetcher.find_metadata_for_object(
            "subnets", self.nutanix_network, error_on_not_found=True
        )["uuid"]
        self.karbon_image_uuid = self.prism_object_fetcher.find_metadata_for_object(
            "images", self.karbon_image, error_on_not_found=True
        )["uuid"]
        request_json = {
            "name": self.name,
            "description": self.description,
            "vm_network": self.nutanix_network_uuid,
            "k8s_config": {
                "service_cluster_ip_range": self.karbon_service_cluster_ip_range,
                "network_cidr": self.karbon_network_cidr,
                "fqdn": "",
                "workers": [],
                "masters": [
                    {
                        "node_pool_name": "",
                        "name": "",
                        "uuid": "",
                        "resource_config": {
                            "cpu": self.master_cpu,
                            "memory_mib": self.master_memory_mib,
                            "image": self.karbon_image_uuid,
                            "disk_mib": self.master_disk_mib,
                        },
                    }
                ],
                "os_flavor": self.os_flavor,
                "network_subnet_len": self.karbon_network_subnet_len,
                "version": self.karbon_version,
            },
            "cluster_ref": self.nutanix_cluster_uuid,
            "logging_config": {"enable_app_logging": False},
            "storage_class_config": {
                "metadata": {"name": "default-storageclass"},
                "spec": {
                    "reclaim_policy": "Delete",
                    "sc_volumes_spec": {
                        "cluster_ref": self.nutanix_cluster_uuid,
                        "user": self.nutanix_cluster_username,
                        "password": self.nutanix_cluster_password,
                        "storage_container": self.nutanix_storage_container,
                        "file_system": "ext4",
                        "flash_mode": False,
                    },
                },
            },
            "etcd_config": {
                "num_instances": 1,
                "name": self.name,
                "nodes": [
                    {
                        "node_pool_name": "",
                        "name": "",
                        "uuid": "",
                        "resource_config": {
                            "cpu": self.etcd_cpu,
                            "memory_mib": self.etcd_memory_mib,
                            "image": self.karbon_image_uuid,
                            "disk_mib": self.etcd_disk_mib,
                        },
                    }
                ],
            },
        }
        request_json["k8s_config"]["workers"] = [
            {
                "node_pool_name": "",
                "name": "",
                "uuid": "",
                "resource_config": {
                    "cpu": self.worker_cpu,
                    "memory_mib": self.worker_memory_mib,
                    "image": self.karbon_image_uuid,
                    "disk_mib": self.worker_disk_mib,
                },
            }
        ] * self.worker_count
        self.logger.info("create request_json: %s" % json.dumps(request_json))
        response_json = self.request_helper.post(
            "/karbon/acs/k8s/cluster", request_json
        )
        self.logger.info("create response_json: %s" % json.dumps(response_json))
        task_uuid = response_json.get("task_uuid")
        if not task_uuid:
            self.module.fail_json(
                msg="failed to retrieve task uuid when creating cluster"
            )
        self.__wait_for_task(task_uuid)
        cluster_obj = self.get_cluster_obj()
        return cluster_obj

    def update_cluster_obj(self, cluster_obj):
        self.logger.info("Entering update_cluster_obj")
        self.__validate_worker_count(cluster_obj)
        current_worker_data = self.__get_current_worker_data(cluster_obj)
        self.logger.info(
            "cluster_object_to_update: %s" % json.dumps(cluster_obj, indent=2)
        )
        self.logger.info("current_worker_data: %s" % json.dumps(current_worker_data))
        current_worker_count = len(current_worker_data)
        cluster_uuid = self.__get_cluster_uuid(cluster_obj)
        worker_pool_uuid = current_worker_data[0]["node_pool_name"]
        if self.worker_count == current_worker_count:
            return cluster_obj
        if self.worker_count < current_worker_count:
            nodes_to_remove = current_worker_count - self.worker_count
            self.__delete_workers(cluster_uuid, current_worker_data, nodes_to_remove)
        if self.worker_count > current_worker_count:
            nodes_to_add = self.worker_count - current_worker_count
            self.__add_workers(cluster_uuid, worker_pool_uuid, nodes_to_add)
        cluster_obj = self.get_cluster_obj()
        self.final_state.changed = True
        return cluster_obj

    def get_cluster_obj(self):
        cluster_obj = self.__get_cluster_obj_raw()
        self.logger.info(
            "get_cluster_obj cluster_obj: %s" % json.dumps(cluster_obj, indent=2)
        )
        if cluster_obj:
            # cluster status overview
            # 1: in progress
            # 2: failed
            # 3: success
            task_status = cluster_obj.get("task_status", 0)
            self.logger.info("get_cluster_obj task_status: %s" % str(task_status))
            if not task_status or task_status > 3:
                self.module.fail_json(
                    msg="Unable to get a valid task_status for cluster with name %s. Please verify manually!"
                    % (self.name)
                )
            if task_status == 2:
                self.module.fail_json(
                    msg="Clusters found with name %s but status is failed! Please remove it!"
                    % (self.name)
                )
            if task_status == 1:
                task_uuid = cluster_obj.get("task_uuid")
                if not task_uuid:
                    self.module.fail_json(
                        msg="Unable to get task_uuid for in progress cluster with name %s. Please verify manually!"
                        % (self.name)
                    )
                self.logger.info(
                    "get_cluster_obj Starting waiting for task : %s" % str(task_uuid)
                )
                self.__wait_for_task(task_uuid)
                return self.get_cluster_obj()
        return cluster_obj

    def delete_cluster_obj(self, cluster_obj):
        cluster_uuid = self.__get_cluster_uuid(cluster_obj)
        response = self.request_helper.delete(
            "/karbon/acs/k8s/cluster/%s" % cluster_uuid
        )
        self.__wait_for_task(response["task_uuid"])

    def get_kubeconfig_file(self, cluster_obj):
        if not self.kubeconfig_download:
            self.logger.info("Not downloading kubeconfig")
            return
        cluster_uuid = self.__get_cluster_uuid(cluster_obj)
        response_json = self.request_helper.get(
            "/karbon/acs/k8s/cluster/%s/kubeconfig" % cluster_uuid
        )
        kube_yml_base64 = response_json.get("yml_config")
        if not kube_yml_base64:
            self.module.fail_json(msg="Was unable to retrieve kubeconfig file")
        kube_yml = self.__decode_base64(kube_yml_base64)
        kube_yaml_full_path = NtnxFileHandler.write_file(
            self.kubeconfig_download_path, kube_yml
        )
        self.final_state.changed = True
        self.final_state.extra["msg"] = "export KUBECONFIG='%s'" % kube_yaml_full_path
        self.final_state.extra["kubeconfig_path"] = kube_yaml_full_path

    def delete_ssh_certificates(self):
        self.__delete_file("%s.pub" % self.ssh_certificates_download_path)
        self.__delete_file(self.ssh_certificates_download_path)

    def delete_kubeconfig_file(self):
        self.__delete_file(self.kubeconfig_download_path)

    def __delete_file(self, path):
        self.logger.info("Deleting file " + path)
        if NtnxFileHandler.file_exists(path):
            self.final_state.changed = True
            kube_yaml_full_path = NtnxFileHandler.delete_file(path)

    def get_ssh_certificates(self, cluster_obj):
        if not self.ssh_certificates_download:
            self.logger.info("Not downloading ssh certificates")
            return
        delimiter = "|||"
        newline = "\n"
        cluster_uuid = self.__get_cluster_uuid(cluster_obj)
        response_json = self.request_helper.get(
            "/karbon/acs/k8s/cluster/%s/node_ssh" % cluster_uuid
        )
        ssh_access_script_base64 = response_json.get("access_script")
        if not ssh_access_script_base64:
            self.module.fail_json(
                msg="Was unable to retrieve ssh access certificates file"
            )
        ssh_access_script = self.__decode_base64(ssh_access_script_base64)
        ssh_access_script = ssh_access_script.replace(newline, delimiter)
        ssh_access_script_splitted = ssh_access_script.split("'")
        ssh_private_key = ssh_access_script_splitted[1].replace(delimiter, newline)
        ssh_cert = ssh_access_script_splitted[3].replace(delimiter, newline)
        ssh_private_key_full_path = NtnxFileHandler.write_file(
            self.ssh_certificates_download_path, ssh_private_key, permissions=0o600
        )
        ssh_public_key_full_path = NtnxFileHandler.write_file(
            "%s.pub" % self.ssh_certificates_download_path, ssh_cert
        )
        self.final_state.changed = True
        self.logger.info(
            "ssh_private_key_full_path: %s" % str(ssh_private_key_full_path)
        )
        self.final_state.extra["ssh_private_key_path"] = ssh_private_key_full_path
        self.logger.info("ssh_public_key_full_path: %s" % str(ssh_public_key_full_path))
        self.final_state.extra["ssh_public_key_path"] = ssh_public_key_full_path

    def get_worker_ips(self, cluster_obj):
        worker_data = self.__get_current_worker_data(cluster_obj)
        return list(map(lambda e: e["resource_config"]["ip_address"], worker_data))

    def __delete_workers(self, cluster_uuid, worker_data, amount):
        tasks = []
        for i in range(0, amount):
            url = "/karbon/acs/k8s/cluster/%s/workers/%s" % (
                cluster_uuid,
                worker_data[i]["name"],
            )
            response_json = self.request_helper.delete(url)
            tasks.append(response_json["task_uuid"])
            time.sleep(5)
        for t in tasks:
            self.__wait_for_task(t)

    def __add_workers(self, cluster_uuid, worker_pool_uuid, amount):
        request_body = {"node_pool_name": worker_pool_uuid, "worker_count": amount}
        response_json = self.request_helper.post(
            "/karbon/acs/k8s/cluster/%s/workers" % cluster_uuid, request_body
        )
        self.__wait_for_task(response_json["task_uuid"])

    def __validate_worker_count(self, cluster_obj=None):
        if self.worker_count < 1:
            self.module.fail_json(
                msg="worker_count must be >=1, was %d" % self.worker_count
            )

    def __get_current_worker_data(self, cluster_obj):
        return cluster_obj["cluster_metadata"]["k8s_config"]["workers"]

    def __get_cluster_obj_raw(self):
        response = self.request_helper.post("/karbon/acs/k8s/cluster/list", {})
        matched_clusters = list(
            filter((lambda e: e["cluster_metadata"]["name"] == self.name), response)
        )
        if len(matched_clusters) == 1:
            return matched_clusters[0]
        elif len(matched_clusters) == 0:
            return None
        else:
            self.module.fail_json(
                msg="Multiple clusters found with name %s. Please verify manually!!"
                % (self.name)
            )

    def __decode_base64(self, base64_str):
        base64_str_bytes = base64_str.encode("ascii")
        kube_yml_bytes = base64.b64decode(base64_str_bytes)
        return kube_yml_bytes.decode("ascii")

    def __get_cluster_uuid(self, cluster_obj):
        cluster_uuid = cluster_obj.get("cluster_metadata", {"uuid": None}).get("uuid")
        if not cluster_uuid:
            self.module.fail_json(msg="Unable to retrieve cluster uuid")
        return cluster_uuid

    def __wait_for_task(self, task_uuid):
        if not self.wait_completion:
            return
        task_state = "RUNNING"
        while task_state.upper() == "RUNNING":
            time.sleep(5)
            response = self.request_helper.get(
                "/karbon/prism/api/nutanix/v3/tasks/%s" % task_uuid
            )
            task_state = response.get("status")
            if not task_state:
                self.module.fail_json(
                    msg="Failed to retrieve task status for task with ID: %s"
                    % task_uuid
                )
