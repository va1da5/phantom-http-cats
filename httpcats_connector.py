#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

import json
import os
import shutil
import tempfile
from typing import Any, Mapping, Tuple

# Phantom App imports
import phantom.app as phantom

# Usage of the consts file is recommended
# from httpcats_consts import *
import requests
from bs4 import BeautifulSoup
from phantom import vault as Vault
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class HttpCatsConnector(BaseConnector):
    def __init__(self):

        # Call the BaseConnectors init first
        super(HttpCatsConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _process_empty_response(
        self, response: requests.Response, action_result: ActionResult
    ) -> RetVal:
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ),
            None,
        )

    def _process_html_response(
        self, response: requests.Response, action_result: ActionResult
    ):

        if "<title>HTTP Cats</title>" in response.text:
            return RetVal(action_result.set_status(phantom.APP_SUCCESS, response.text))

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except:  # noqa
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(
            status_code, error_text
        )

        message = message.replace("{", "{{").replace("}", "}}")
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(
        self, r: requests.Response, action_result: ActionResult
    ) -> RetVal:
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to parse JSON response. Error: {0}".format(str(e)),
                ),
                None,
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_image_response(
        self, r: requests.Response, action_result: ActionResult
    ) -> Tuple[bool, bytes]:

        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, r.content)

    def _process_response(
        self, r: requests.Response, action_result: ActionResult
    ) -> RetVal:
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        if "jpeg" in r.headers.get("Content-Type", ""):
            return self._process_image_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(
        self, endpoint: str, action_result: ActionResult, method: str = "get", **kwargs
    ):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Invalid method: {0}".format(method)
                ),
                resp_json,
            )

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                url,
                # auth=(username, password),  # basic authentication
                verify=config.get("verify_server_cert", False),
                **kwargs,
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error Connecting to server. Details: {0}".format(str(e)),
                ),
                resp_json,
            )

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param: Mapping[str, Any]):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint")
        # make rest call
        ret_val, response = self._make_rest_call(
            "/", action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _move_file_to_vault(
        self,
        container_id: str,
        file_size: int,
        type_str: str,
        local_file_path: str,
        action_result: ActionResult,
    ) -> Tuple[bool, Mapping[str, Any]]:
        """Moves a local file to vault.
        Args:
            container_id (str): ID of the container in which we need to add vault file
            file_size (int): size of file
            type_str (str): file type
            local_file_path (str): path where file is stored
            action_result (ActionResult): object of ActionResult class
        Return:
             Tuple (RetVal):
                * bool: status success/failure
                * dict or None: vault details, if successful
        """

        self.send_progress(phantom.APP_PROG_ADDING_TO_VAULT)

        vault_details = {
            phantom.APP_JSON_SIZE: file_size,
            phantom.APP_JSON_TYPE: type_str,
            phantom.APP_JSON_CONTAINS: [type_str],
            phantom.APP_JSON_ACTION_NAME: self.get_action_name(),
            phantom.APP_JSON_APP_RUN_ID: self.get_app_run_id(),
        }

        file_name = os.path.basename(local_file_path)

        # Adding file to vault
        try:
            success, message, vault_id = Vault.vault_add(
                container_id, local_file_path, file_name
            )
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to get Vault item details from Phantom. Details: {0}".format(
                        err_msg
                    ),
                ),
                None,
            )

        # Updating report data with vault details
        if success:
            success, message, info = Vault.vault_info(
                vault_id, file_name, container_id, trace=True
            )
            vault_details[phantom.APP_JSON_VAULT_ID] = vault_id
            vault_details["filename"] = file_name
            vault_details["file_id"] = info[0]["id"]
            if success:
                self.send_progress(
                    "Success adding file to Vault. Vault ID: {}".format(vault_id)
                )
            return RetVal(phantom.APP_SUCCESS, vault_details)

        # Error while adding file to vault
        self.debug_print("ERROR: Adding file to vault:", message)
        action_result.append_to_message(". {}".format(message))

        # set the action_result status to error, the handler function
        # will most probably return as is
        return RetVal(phantom.APP_ERROR, None)

    def _handle_get_status(self, param: Mapping[str, Any]):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary(
            {"http_status_code": param["http_status_code"]}
        )

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        http_status_code = param["http_status_code"]

        ret_val, response = self._make_rest_call(
            f"/{http_status_code}", action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        filename = f"{http_status_code}.jpeg"

        self.send_progress("Saving file to disk")

        temp_dir = tempfile.mkdtemp()
        try:
            file_path = os.path.join(temp_dir, filename)
            with open(file_path, "wb") as file_obj:
                file_obj.write(response)
        except Exception as e:
            self.debug_print("Error creating file")
            shutil.rmtree(temp_dir)
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Error creating file. Error Details: {err_msg}"
            )

        container_id = self.get_container_id()

        try:
            vault_list = Vault.vault_info(container_id=container_id)
        except Exception as exc:
            err_msg = self._get_error_message_from_exception(exc)
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Unable to get Vault item details from Phantom. Details: {err_msg}",
            )

        vault_details = {}
        try:
            # Iterate through each vault item in the container and compare name and size of file
            for vault in vault_list[2]:
                if vault.get("name") == filename and vault.get(
                    "size"
                ) == os.path.getsize(file_path):
                    self.send_progress("HTTP Cat already present in Vault")
                    vault_details = {
                        phantom.APP_JSON_SIZE: vault.get("size"),
                        phantom.APP_JSON_VAULT_ID: vault.get(phantom.APP_JSON_VAULT_ID),
                        "filename": filename,
                    }
        except Exception as exc:
            err_msg = self._get_error_message_from_exception(exc)
            return action_result.set_status(
                phantom.APP_ERROR, f"Error details: {err_msg}"
            )

        if not vault_details:
            vault_ret_val, vault_details = self._move_file_to_vault(
                container_id,
                os.path.getsize(file_path),
                "jpeg",
                file_path,
                action_result,
            )
            # Check if something went wrong while moving file to vault
            if phantom.is_fail(vault_ret_val):
                return action_result.set_status(
                    phantom.APP_ERROR, "Could not move file to vault"
                )

        shutil.rmtree(temp_dir)

        summary_data[phantom.APP_JSON_VAULT_ID] = vault_details[
            phantom.APP_JSON_VAULT_ID
        ]
        summary_data["file_id"] = vault_details["file_id"]

        message = f"HTTP Cat added to Vault: {vault_details[phantom.APP_JSON_VAULT_ID]}"

        return action_result.set_status(phantom.APP_SUCCESS, message)

    def handle_action(self, param: Mapping[str, Any]):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == "get_status":
            ret_val = self._handle_get_status(param)

        if action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()
        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config.get("base_url")

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = HttpCatsConnector._get_phantom_base_url() + "/login"

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = HttpCatsConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == "__main__":
    main()
