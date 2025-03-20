import os
import re
import subprocess
import time
from aioresponses import aioresponses
import json as json_util


from semantic_version import Spec, Version
from async_hvac import Client


class ServerManager(object):

    def __init__(self, config_path: str, client: Client):
        self.config_path = config_path
        self.client = client
        self.keys = None
        self.root_token = None

        self._process = None

    def start(self):
        vault_bin = os.environ.get("VAULT_BINARY", "vault")
        command = [vault_bin, "server", "-config=" + self.config_path]

        self._process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        attempts_left = 20
        last_exception = None
        while attempts_left > 0:
            try:
                self.client.is_initialized()
                return
            except Exception as ex:
                print("Waiting for Vault to start")

                time.sleep(0.5)

                attempts_left -= 1
                last_exception = ex
        raise last_exception
        # raise Exception('Unable to start Vault in background: {0}'.format(last_exception))

    def stop(self):
        self.client.close()
        self._process.kill()

    def initialize(self):

        result = self.client.initialize()
        self.root_token = result["root_token"]
        self.keys = result["keys"]

    def unseal(self):
        return self.client.unseal_multi(self.keys)


VERSION_REGEX = re.compile("Vault v([0-9]+)")
VERSION_REGEX_2 = re.compile(r"Vault v(\d+\.\d+\.\d+)")


def get_vault_version():
    """Returns the current Vault version"""
    vault_bin = os.environ.get("VAULT_BINARY", "vault")
    output = subprocess.check_output([vault_bin, "version"]).decode("ascii")
    return VERSION_REGEX_2.match(output).group(1)


def match_version(spec):
    vault_bin = os.environ.get("VAULT_BINARY", "vault")
    output = subprocess.check_output([vault_bin, "version"]).decode("ascii")
    version = Version(VERSION_REGEX.match(output).group(1))

    return Spec(spec).match(version)


class RequestsMocker(aioresponses):

    def __init__(self):
        super(RequestsMocker, self).__init__()

    def register_uri(self, method="GET", url="", status_code=200, json=None):
        if json:
            json = json_util.dumps(json)
        else:
            json = ""
        if method == "GET":
            self.get(url=url, status=status_code, body=json)
        if method == "POST":
            self.post(url=url, status=status_code, body=json)
        if method == "DELETE":
            self.delete(url=url, status=status_code, body=json)


def get_popen_kwargs(**popen_kwargs):
    """Helper method to add `encoding='utf-8'` to subprocess.Popen.

    :param popen_kwargs: List of keyword arguments to conditionally mutate
    :type popen_kwargs: **kwargs
    :return: Conditionally updated list of keyword arguments
    :rtype: dict
    """
    popen_kwargs["encoding"] = "utf-8"
    return popen_kwargs


def decode_generated_root_token(encoded_token, otp, url="localhost"):
    """Decode a newly generated root token via Vault CLI.

    :param encoded_token: The token to decode.
    :type encoded_token: str | unicode
    :param otp: OTP code to use when decoding the token.
    :type otp: str | unicode
    :return: The decoded root token.
    :rtype: str | unicode
    """
    command = [os.environ.get("VAULT_BINARY", "vault")]
    command.append("operator")

    command.extend(
        [
            "generate-root",
            "-tls-skip-verify",
            "-decode",
            encoded_token,
            "-otp",
            otp,
        ]
    )
    process = subprocess.Popen(
        **get_popen_kwargs(args=command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    )

    stdout, stderr = process.communicate()

    try:
        # On the off chance VAULT_FORMAT=json or such is set in the test environment:
        new_token = json_util.loads(stdout)["token"]
    except ValueError:
        new_token = stdout.replace("Root token:", "")
    new_token = new_token.strip()
    return new_token
