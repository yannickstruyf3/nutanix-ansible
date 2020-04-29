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
except Exception as e:
    raise Exception(f"Failed to import: {e}")


class NtnxFileHandler:
    def __init__(self):
        pass

    @staticmethod
    def file_exists(file_path):
        return os.path.exists(file_path)

    @staticmethod
    def delete_file(file_path):
        if NtnxFileHandler.file_exists:
            os.remove(file_path)

    @staticmethod
    def write_file(path, content, permissions=0o644):
        file = open(path, "w")
        file.write(content)
        file.close()
        full_path = os.path.abspath(path)
        os.chmod(full_path, permissions)
        return full_path


class NtnxLogger:
    def __init__(self, module_name, debug_enabled):
        self.debug_enabled = debug_enabled
        self.module_name = module_name
        self.logger = None

    def __create_logger(self):
        self.logger = logging.getLogger(self.module_name)
        handler = logging.FileHandler(self.module_name + ".log")
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def info(self, msg):
        if self.debug_enabled:
            if not self.logger:
                self.__create_logger()
            self.logger.info(msg)


class FinalState:
    def __init__(self):
        self.changed = False
        self.state = "absent"
        self.extra = {}

    def get_final_state(self):
        return_obj = {"changed": self.changed, "state": self.state}
        if not self.extra:
            self.extra = {}
        for e in self.extra:
            return_obj[e] = self.extra.get(e)
        return return_obj


class ConnectionWrapper:
    def __init__(self, pc_host, pc_port, pc_username, pc_password, ssl_verify=False):
        self.pc_host = pc_host
        self.pc_port = pc_port
        self.pc_username = pc_username
        self.pc_password = pc_password
        self.ssl_verify = ssl_verify


class PrismObjectFetcher:
    def __init__(self, logger, request_helper, prefix="/karbon"):
        self.logger = logger
        self.prism_api_prefix = "%s/prism/api/nutanix/v3" % prefix
        self.request_helper = request_helper

    def find_metadata_for_object(
        self, obj_type, obj_name=None, error_on_not_found=False
    ):
        filter_str = ""
        entity_parser = self.__entity_parser_multiple
        if obj_name:
            filter_str = "name==%s" % (obj_name)
            entity_parser = self.__entity_parser_single
        amount_of_entries = 250
        offset = 0
        j = {"filter": filter_str, "length": amount_of_entries, "offset": offset}
        request_url_suffix = "%s/%s/list" % (self.prism_api_prefix, obj_type)
        self.logger.info("request_url_suffix: %s" % request_url_suffix)
        self.logger.info("j: %s" % json.dumps(j))
        result = self.request_helper.post(request_url_suffix, j)
        self.logger.info("find_metadata_for_object: %s" % json.dumps(result))
        entities = result.get("entities", [])
        parsed_entities = entity_parser(
            entities, obj_type, obj_name, error_on_not_found
        )
        return parsed_entities

    def __entity_parser_single(self, entities, obj_type, obj_name, error_on_not_found):
        if len(entities) == 0:
            if error_on_not_found:
                raise Exception(
                    "Unable to find %s object found for name %s" % (obj_type, obj_name)
                )
            return None
        if len(entities) > 1:
            # failback in case of bad filtering
            entities = list(filter(lambda e: e["spec"]["name"] == obj_name, entities))
            if len(entities) > 1:
                raise Exception(
                    "More than one %s object found for name %s" % (obj_type, obj_name)
                )
        return entities[0]["metadata"]

    def __entity_parser_multiple(
        self, entities, obj_type, obj_name, error_on_not_found
    ):
        if len(entities) == 0:
            if error_on_not_found:
                raise Exception("Unable to find %s objects" % (obj_type))
            return []
        return list(map(lambda e: e["metadata"], entities))


class RequestHelper:
    cookie = None

    def __init__(self, module, logger, connection_wrapper, requires_cookie=False):
        self.logger = logger
        self.connection_wrapper = connection_wrapper
        self.ntnx_url = "https://%s:%s" % (
            self.connection_wrapper.pc_host,
            connection_wrapper.pc_port,
        )
        self.headers = {"content-type": "application/json"}
        self.requires_cookie = requires_cookie
        self.module = module

    def put(self, url_suffix, body, error_on_bad_request=True):
        url = "%s%s" % (self.ntnx_url, url_suffix)
        self.logger.info("put url: %s" % url)
        response = requests.put(
            url,
            headers=self.headers,
            cookies=self.__get_cookie(),
            auth=HTTPBasicAuth(
                self.connection_wrapper.pc_username, self.connection_wrapper.pc_password
            ),
            verify=self.connection_wrapper.ssl_verify,
            json=body,
        )
        self.logger.info("response: " + str(response))
        return self.__parse_http_response(
            response, url, error_on_bad_request=error_on_bad_request
        )

    def post(self, url_suffix, body, error_on_bad_request=True):
        url = "%s%s" % (self.ntnx_url, url_suffix)
        self.logger.info("POST %s" % url)
        self.logger.info("payload %s" % json.dumps(body, indent=2))
        response = requests.post(
            url,
            headers=self.headers,
            cookies=self.__get_cookie(),
            auth=HTTPBasicAuth(
                self.connection_wrapper.pc_username, self.connection_wrapper.pc_password
            ),
            verify=self.connection_wrapper.ssl_verify,
            json=body,
        )
        return self.__parse_http_response(
            response, url, error_on_bad_request=error_on_bad_request
        )

    def delete(self, url_suffix, error_on_bad_request=True):
        url = "%s%s" % (self.ntnx_url, url_suffix)
        self.logger.info("DELETE %s" % url)
        response = requests.delete(
            url,
            headers=self.headers,
            cookies=self.__get_cookie(),
            auth=HTTPBasicAuth(
                self.connection_wrapper.pc_username, self.connection_wrapper.pc_password
            ),
            verify=self.connection_wrapper.ssl_verify,
        )
        return self.__parse_http_response(
            response, url, error_on_bad_request=error_on_bad_request
        )

    def get(self, url_suffix, error_on_bad_request=True):
        url = "%s%s" % (self.ntnx_url, url_suffix)
        self.logger.info("GET %s" % url)
        response = requests.get(
            url,
            headers=self.headers,
            cookies=self.__get_cookie(),
            auth=HTTPBasicAuth(
                self.connection_wrapper.pc_username, self.connection_wrapper.pc_password
            ),
            verify=self.connection_wrapper.ssl_verify,
        )
        self.logger.info("get response: %s" % str(response))
        self.logger.info("get response: %s" % str(response.text))
        return self.__parse_http_response(
            response, url, error_on_bad_request=error_on_bad_request
        )

    def __parse_http_response(self, response, invoke_reason, error_on_bad_request):
        status_code = response.status_code
        if status_code < 200 or status_code > 299:
            if error_on_bad_request:
                self.module.fail_json(
                    msg="Bad HTTP response status code %s received for %s: %s"
                    % (status_code, invoke_reason, response.text)
                )
            return None
        return response.json()

    def __get_cookie(self):
        if not self.requires_cookie:
            return {}
        if self.cookie:
            return self.cookie
        url = "%s/karbon/prism/api/nutanix/v3/batch" % (self.ntnx_url)
        login_body = {
            "action_on_failure": "CONTINUE",
            "execution_order": "SEQUENTIAL",
            "api_request_list": [
                {"operation": "GET", "path_and_params": "/api/nutanix/v3/users/me"},
                {"operation": "GET", "path_and_params": "/api/nutanix/v3/users/info"},
            ],
            "api_version": "3.0",
        }
        response = requests.post(
            url,
            headers=self.headers,
            auth=HTTPBasicAuth(
                self.connection_wrapper.pc_username, self.connection_wrapper.pc_password
            ),
            verify=self.connection_wrapper.ssl_verify,
            json=login_body,
        )
        self.__parse_http_response(
            response, "getting cookie", error_on_bad_request=True
        )
        cookies = response.cookies
        if "NTNX_IGW_SESSION" not in cookies:
            self.module.fail_json(msg="Unable to retrieve authentication cookie!")
        self.cookie = {"NTNX_IGW_SESSION": cookies["NTNX_IGW_SESSION"]}
        return self.cookie
