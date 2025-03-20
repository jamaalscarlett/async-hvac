import asyncio
from unittest import IsolatedAsyncioTestCase


from async_hvac import AsyncClient, Client, exceptions
from async_hvac.tests import util
from time import sleep

loop = asyncio.new_event_loop()


def create_client(sync=False, **kwargs):
    if sync:
        return Client(
            url="https://127.0.0.1:8200",
            cert=("test-fixtures/client-cert.pem", "test-fixtures/client-key.pem"),
            verify="test-fixtures/server-cert.pem",
            loop=loop,
            **kwargs
        )
    else:
        return AsyncClient(
            url="https://127.0.0.1:8200",
            cert=("test-fixtures/client-cert.pem", "test-fixtures/client-key.pem"),
            verify="test-fixtures/server-cert.pem",
            loop=IntegrationTest.get_loop(),
            # loop=loop,
            **kwargs
        )


class IntegrationTest(IsolatedAsyncioTestCase):
    def get_loop():
        return asyncio.get_running_loop()

    @classmethod
    def setUpClass(cls):
        cls.manager = util.ServerManager(
            config_path="test-fixtures/vault-tls.hcl", client=create_client(sync=True)
        )
        cls.manager.start()
        cls.manager.initialize()
        cls.manager.unseal()

    @classmethod
    def tearDownClass(cls):
        cls.manager.stop()

    def root_token(self):
        cls = type(self)
        return cls.manager.root_token

    def get_client(self) -> Client:
        return create_client(token=self.root_token())

    async def test_verifiy_false(self):
        client = AsyncClient(
            url="https://127.0.0.1:8200", verify=False, loop=asyncio.get_running_loop()
        )

        assert "ha_enabled" in (await client.ha_status)

    async def test_unseal_multi(self):
        cls = type(self)
        client = self.get_client()
        await client.seal()

        keys = cls.manager.keys

        result = await client.unseal_multi(keys[0:2])

        assert result["sealed"]
        assert result["progress"] == 2

        result = await client.unseal_reset()
        assert result["progress"] == 0
        result = await client.unseal_multi(keys[1:3])
        assert result["sealed"]
        assert result["progress"] == 2
        result = await client.unseal_multi(keys[0:1])
        result = await client.unseal_multi(keys[2:3])
        assert not result["sealed"]

    async def test_seal_unseal(self):
        cls = type(self)
        client = self.get_client()
        assert not (await client.is_sealed())

        await client.seal()

        assert await client.is_sealed()

        cls.manager.unseal()

        assert not (await client.is_sealed())

    async def test_ha_status(self):
        client = self.get_client()
        assert "ha_enabled" in (await client.ha_status)

    async def init_client(self, client):
        response = await client.list_secret_backends()
        if "secret/" not in response.keys():
            await client.enable_secret_backend("kv", mount_point="secret")

    async def test_generic_secret_backend(self):
        client = self.get_client()
        await self.init_client(client)
        await client.write("secret/foo", zap="zip")
        result = await client.read("secret/foo")

        assert result["data"]["zap"] == "zip"

        await client.delete("secret/foo")

    async def test_list_directory(self):
        client = self.get_client()
        await self.init_client(client)

        await client.write("secret/test-list/bar/foo", value="bar")
        await client.write("secret/test-list/foo", value="bar")
        result = await client.list("secret/test-list")

        assert result["data"]["keys"] == ["bar/", "foo"]

        await client.delete("secret/test-list/bar/foo")
        await client.delete("secret/test-list/foo")

    async def test_write_with_response(self):
        client = self.get_client()
        await self.init_client(client)
        if "transit/" in (await client.list_secret_backends()):
            await client.disable_secret_backend("transit")
        await client.enable_secret_backend("transit")

        plaintext = "test"

        await client.write("transit/keys/foo")

        result = await client.write("transit/encrypt/foo", plaintext=plaintext)
        ciphertext = result["data"]["ciphertext"]

        result = await client.write("transit/decrypt/foo", ciphertext=ciphertext)
        assert result["data"]["plaintext"] == plaintext

    async def test_wrap_write(self):
        client = self.get_client()
        if "approle/" not in (await client.list_auth_backends()):
            await client.enable_auth_backend("approle")

        await client.write("auth/approle/role/testrole")
        result = await client.write(
            "auth/approle/role/testrole/secret-id", wrap_ttl="10s"
        )
        assert "token" in result["wrap_info"]
        await client.unwrap(result["wrap_info"]["token"])
        await client.disable_auth_backend("approle")

    async def test_read_nonexistent_key(self):
        client = self.get_client()
        assert not (await client.read("secret/I/dont/exist"))

    async def test_auth_backend_manipulation(self):
        client = self.get_client()
        assert "github/" not in (await client.list_auth_backends())

        await client.enable_auth_backend("github")
        assert "github/" in (await client.list_auth_backends())

        client.token = self.root_token()
        await client.disable_auth_backend("github")
        assert "github/" not in (await client.list_auth_backends())

    async def test_secret_backend_manipulation(self):
        client = self.get_client()
        assert "test/" not in (await client.list_secret_backends())

        await client.enable_secret_backend("generic", mount_point="test")
        assert "test/" in (await client.list_secret_backends())

        secret_backend_tuning = await client.get_secret_backend_tuning(
            "generic", mount_point="test"
        )
        self.assertEqual(secret_backend_tuning["max_lease_ttl"], 2764800)
        self.assertEqual(secret_backend_tuning["default_lease_ttl"], 2764800)

        await client.tune_secret_backend(
            "generic",
            mount_point="test",
            default_lease_ttl="3600s",
            max_lease_ttl="8600s",
        )
        secret_backend_tuning = await client.get_secret_backend_tuning(
            "generic", mount_point="test"
        )

        assert "max_lease_ttl" in secret_backend_tuning
        self.assertEqual(secret_backend_tuning["max_lease_ttl"], 8600)
        assert "default_lease_ttl" in secret_backend_tuning
        self.assertEqual(secret_backend_tuning["default_lease_ttl"], 3600)

        await client.remount_secret_backend("test", "foobar")
        sleep(2)
        backends = await client.list_secret_backends()
        assert "test/" not in backends
        assert "foobar/" in backends

        client.token = self.root_token()
        await client.disable_secret_backend("foobar")
        assert "foobar/" not in (await client.list_secret_backends())

    async def test_audit_backend_manipulation(self):
        client = self.get_client()
        assert "tmpfile/" not in (await client.list_audit_backends())

        options = {"path": "/tmp/vault.audit.log"}

        await client.enable_audit_backend("file", options=options, name="tmpfile")
        assert "tmpfile/" in (await client.list_audit_backends())

        client.token = self.root_token()
        await client.disable_audit_backend("tmpfile")
        assert "tmpfile/" not in (await client.list_audit_backends())

    async def prep_policy(self, client, name):
        text = """
        path "sys" {
            policy = "deny"
        }
        path "secret" {
            policy = "write"
        }
        """
        obj = {"path": {"sys": {"policy": "deny"}, "secret": {"policy": "write"}}}
        await client.set_policy(name, text)
        return text, obj

    async def test_policy_manipulation(self):
        client = self.get_client()
        assert "root" in (await client.list_policies())
        assert (await client.get_policy("test")) is None
        policy, parsed_policy = await self.prep_policy(client, "test")
        assert "test" in (await client.list_policies())
        assert policy == (await client.get_policy("test"))
        assert parsed_policy == (await client.get_policy("test", parse=True))

        await client.delete_policy("test")
        assert "test" not in (await client.list_policies())

    async def test_json_policy_manipulation(self):
        client = self.get_client()
        assert "root" in (await client.list_policies())

        policy = {"path": {"sys": {"policy": "deny"}, "secret": {"policy": "write"}}}

        await client.set_policy("test", policy)
        assert "test" in (await client.list_policies())

        await client.delete_policy("test")
        assert "test" not in (await client.list_policies())

    async def test_auth_token_manipulation(self):
        client = self.get_client()
        result = await client.create_token(lease="1h", renewable=True)
        assert result["auth"]["client_token"]

        lookup = await client.lookup_token(result["auth"]["client_token"])
        assert result["auth"]["client_token"] == lookup["data"]["id"]

        renew = await client.renew_token(lookup["data"]["id"])
        assert result["auth"]["client_token"] == renew["auth"]["client_token"]

        await client.revoke_token(lookup["data"]["id"])

        try:
            lookup = await client.lookup_token(result["auth"]["client_token"])
            assert False
        except exceptions.Forbidden:
            assert True
        except exceptions.InvalidPath:
            assert True
        except exceptions.InvalidRequest:
            assert True

    async def test_userpass_auth(self):
        client = self.get_client()
        if "userpass/" in (await client.list_auth_backends()):
            await client.disable_auth_backend("userpass")

        await client.enable_auth_backend("userpass")

        await client.write(
            "auth/userpass/users/testuser", password="testpass", policies="not_root"
        )

        result = await client.auth_userpass("testuser", "testpass")

        assert client.token == result["auth"]["client_token"]
        assert await client.is_authenticated()

        client.token = self.root_token()
        await client.disable_auth_backend("userpass")

    async def test_create_userpass(self):
        client = self.get_client()
        if "userpass/" not in (await client.list_auth_backends()):
            await client.enable_auth_backend("userpass")

        await client.create_userpass(
            "testcreateuser", "testcreateuserpass", policies="not_root"
        )

        result = await client.auth_userpass("testcreateuser", "testcreateuserpass")

        assert client.token == result["auth"]["client_token"]
        assert await client.is_authenticated()

        # Test ttl:
        client.token = self.root_token()
        await client.create_userpass(
            "testcreateuser", "testcreateuserpass", policies="not_root", ttl="10s"
        )
        client.token = result["auth"]["client_token"]

        result = await client.auth_userpass("testcreateuser", "testcreateuserpass")

        assert result["auth"]["lease_duration"] == 10

        client.token = self.root_token()
        await client.disable_auth_backend("userpass")

    async def test_list_userpass(self):
        client = self.get_client()
        if "userpass/" not in (await client.list_auth_backends()):
            await client.enable_auth_backend("userpass")

        # add some users and confirm that they show up in the list
        await client.create_userpass(
            "testuserone", "testuseronepass", policies="not_root"
        )
        await client.create_userpass(
            "testusertwo", "testusertwopass", policies="not_root"
        )

        user_list = await client.list_userpass()
        assert "testuserone" in user_list["data"]["keys"]
        assert "testusertwo" in user_list["data"]["keys"]

        # delete all the users and confirm that list_userpass() doesn't fail
        for user in user_list["data"]["keys"]:
            await client.delete_userpass(user)

        no_users_list = await client.list_userpass()
        assert no_users_list is None

    async def test_read_userpass(self):
        client = self.get_client()
        if "userpass/" not in (await client.list_auth_backends()):
            await client.enable_auth_backend("userpass")

        # create user to read
        await client.create_userpass("readme", "mypassword", policies="not_root")

        # test that user can be read
        read_user = await client.read_userpass("readme")
        assert "not_root" in read_user["data"]["policies"]

        # teardown
        await client.disable_auth_backend("userpass")

    async def test_update_userpass_policies(self):
        client = self.get_client()
        if "userpass/" not in (await client.list_auth_backends()):
            await client.enable_auth_backend("userpass")

        # create user and then update its policies
        await client.create_userpass(
            "updatemypolicies", "mypassword", policies="not_root"
        )
        await client.update_userpass_policies(
            "updatemypolicies", policies="somethingelse"
        )

        # test that policies have changed
        updated_user = await client.read_userpass("updatemypolicies")
        assert "somethingelse" in updated_user["data"]["policies"]

        # teardown
        await client.disable_auth_backend("userpass")

    async def test_update_userpass_password(self):
        client = self.get_client()
        if "userpass/" not in (await client.list_auth_backends()):
            await client.enable_auth_backend("userpass")

        # create user and then change its password
        await client.create_userpass("changeme", "mypassword", policies="not_root")
        await client.update_userpass_password("changeme", "mynewpassword")

        # test that new password authenticates user
        result = await client.auth_userpass("changeme", "mynewpassword")
        assert client.token == result["auth"]["client_token"]
        assert await client.is_authenticated()

        # teardown
        client.token = self.root_token()
        await client.disable_auth_backend("userpass")

    async def test_delete_userpass(self):
        client = self.get_client()
        if "userpass/" not in (await client.list_auth_backends()):
            await client.enable_auth_backend("userpass")

        await client.create_userpass(
            "testcreateuser", "testcreateuserpass", policies="not_root"
        )

        result = await client.auth_userpass("testcreateuser", "testcreateuserpass")

        assert client.token == result["auth"]["client_token"]
        assert await client.is_authenticated()

        client.token = self.root_token()
        await client.delete_userpass("testcreateuser")
        with self.assertRaises(exceptions.InvalidRequest):
            await client.auth_userpass("testcreateuser", "testcreateuserpass")

    async def test_cubbyhole_auth(self):
        client = self.get_client()
        orig_token = client.token

        resp = await client.create_token(lease="6h", wrap_ttl="1h")
        assert resp["wrap_info"]["ttl"] == 3600

        wrapped_token = resp["wrap_info"]["token"]
        await client.auth_cubbyhole(wrapped_token)
        assert client.token != orig_token
        assert client.token != wrapped_token
        assert await client.is_authenticated()

        client.token = orig_token
        assert await client.is_authenticated()

    async def test_create_role(self):
        client = self.get_client()
        if "approle/" in (await client.list_auth_backends()):
            await client.disable_auth_backend("approle")
        await client.enable_auth_backend("approle")

        await client.create_role("testrole")

        result = await client.read("auth/approle/role/testrole")
        lib_result = await client.get_role("testrole")
        del result["request_id"]
        del lib_result["request_id"]

        assert result == lib_result
        client.token = self.root_token()
        await client.disable_auth_backend("approle")

    async def test_delete_role(self):
        client = self.get_client()
        test_role_name = "test-role"
        if "approle/" in (await client.list_auth_backends()):
            await client.disable_auth_backend("approle")
        await client.enable_auth_backend("approle")

        await client.create_role(test_role_name)
        # We add a second dummy test role so we can still hit the /role?list=true route after deleting the first role
        await client.create_role("test-role-2")

        # Ensure our created role shows up when calling list_roles as expected
        result = await client.list_roles()
        actual_list_role_keys = result["data"]["keys"]
        self.assertIn(
            member=test_role_name,
            container=actual_list_role_keys,
        )

        # Now delete the role and verify its absence when calling list_roles
        await client.delete_role(test_role_name)
        result = await client.list_roles()
        actual_list_role_keys = result["data"]["keys"]
        self.assertNotIn(
            member=test_role_name,
            container=actual_list_role_keys,
        )

        # reset test environment
        client.token = self.root_token()
        await client.disable_auth_backend("approle")

    async def test_create_delete_role_secret_id(self):
        client = self.get_client()
        if "approle/" in (await client.list_auth_backends()):
            await client.disable_auth_backend("approle")
        await client.enable_auth_backend("approle")

        await client.create_role("testrole")
        create_result = await client.create_role_secret_id("testrole", {"foo": "bar"})
        secret_id = create_result["data"]["secret_id"]
        result = await client.get_role_secret_id("testrole", secret_id)
        assert result["data"]["metadata"]["foo"] == "bar"
        await client.delete_role_secret_id("testrole", secret_id)
        assert (await client.get_role_secret_id("testrole", secret_id)) is None
        client.token = self.root_token()
        await client.disable_auth_backend("approle")

    async def test_auth_approle(self):
        client = self.get_client()
        if "approle/" in (await client.list_auth_backends()):
            await client.disable_auth_backend("approle")
        await client.enable_auth_backend("approle")

        await client.create_role("testrole")
        create_result = await client.create_role_secret_id("testrole", {"foo": "bar"})
        secret_id = create_result["data"]["secret_id"]
        role_id = await client.get_role_id("testrole")
        result = await client.auth_approle(role_id, secret_id)
        assert result["auth"]["metadata"]["foo"] == "bar"
        assert client.token == result["auth"]["client_token"]
        assert await client.is_authenticated()
        client.token = self.root_token()
        await client.disable_auth_backend("approle")

    async def _test_auth_approle_dont_use_token(self):
        client = self.get_client()
        if "approle/" in (await client.list_auth_backends()):
            await client.disable_auth_backend("approle")
        await client.enable_auth_backend("approle")

        await client.create_role("testrole")
        create_result = await client.create_role_secret_id("testrole", {"foo": "bar"})
        secret_id = create_result["data"]["secret_id"]
        role_id = await client.get_role_id("testrole")
        result = await client.auth_approle(role_id, secret_id, use_token=False)
        assert result["auth"]["metadata"]["foo"] == "bar"
        assert client.token != result["auth"]["client_token"]
        client.token = self.root_token()
        await client.disable_auth_backend("approle")

    async def test_transit_read_write(self):
        client = self.get_client()
        if "transit/" in (await client.list_secret_backends()):
            await client.disable_secret_backend("transit")
        await client.enable_secret_backend("transit")

        await client.transit_create_key("foo")
        result = await client.transit_read_key("foo")
        assert not result["data"]["exportable"]

        await client.transit_create_key(
            "foo_export", exportable=True, key_type="ed25519"
        )
        result = await client.transit_read_key("foo_export")
        assert result["data"]["exportable"]
        assert result["data"]["type"] == "ed25519"

        await client.enable_secret_backend("transit", mount_point="bar")
        await client.transit_create_key("foo", mount_point="bar")
        result = await client.transit_read_key("foo", mount_point="bar")
        assert not result["data"]["exportable"]

    async def test_transit_list_keys(self):
        client = self.get_client()
        if "transit/" in (await client.list_secret_backends()):
            await client.disable_secret_backend("transit")
        await client.enable_secret_backend("transit")

        await client.transit_create_key("foo1")
        await client.transit_create_key("foo2")
        await client.transit_create_key("foo3")

        result = await client.transit_list_keys()
        assert result["data"]["keys"] == ["foo1", "foo2", "foo3"]

    async def test_transit_update_delete_keys(self):
        client = self.get_client()
        if "transit/" in (await client.list_secret_backends()):
            await client.disable_secret_backend("transit")
        await client.enable_secret_backend("transit")

        await client.transit_create_key("foo")
        await client.transit_update_key("foo", deletion_allowed=True)
        result = await client.transit_read_key("foo")
        assert result["data"]["deletion_allowed"]

        await client.transit_delete_key("foo")

        try:
            await client.transit_read_key("foo")
        except exceptions.InvalidPath:
            assert True
        else:
            assert False

    async def test_transit_rotate_key(self):
        client = self.get_client()
        if "transit/" in (await client.list_secret_backends()):
            await client.disable_secret_backend("transit")
        await client.enable_secret_backend("transit")

        await client.transit_create_key("foo")

        await client.transit_rotate_key("foo")
        response = await client.transit_read_key("foo")
        assert "2" in response["data"]["keys"]

        await client.transit_rotate_key("foo")
        response = await client.transit_read_key("foo")
        assert "3" in response["data"]["keys"]

    async def test_transit_export_key(self):
        client = self.get_client()
        if "transit/" in (await client.list_secret_backends()):
            await client.disable_secret_backend("transit")
        await client.enable_secret_backend("transit")

        await client.transit_create_key("foo", exportable=True)
        response = await client.transit_export_key("foo", key_type="encryption-key")
        assert response is not None

    async def test_transit_encrypt_data(self):
        client = self.get_client()
        if "transit/" in (await client.list_secret_backends()):
            await client.disable_secret_backend("transit")
        await client.enable_secret_backend("transit")

        await client.transit_create_key("foo")
        ciphertext_resp = (await client.transit_encrypt_data("foo", "abbaabba"))[
            "data"
        ]["ciphertext"]
        plaintext_resp = (await client.transit_decrypt_data("foo", ciphertext_resp))[
            "data"
        ]["plaintext"]
        assert plaintext_resp == "abbaabba"

    async def test_transit_rewrap_data(self):
        client = self.get_client()
        if "transit/" in (await client.list_secret_backends()):
            await client.disable_secret_backend("transit")
        await client.enable_secret_backend("transit")

        await client.transit_create_key("foo")
        ciphertext_resp = (await client.transit_encrypt_data("foo", "abbaabba"))[
            "data"
        ]["ciphertext"]

        await client.transit_rotate_key("foo")
        response_wrap = (
            await client.transit_rewrap_data("foo", ciphertext=ciphertext_resp)
        )["data"]["ciphertext"]
        plaintext_resp = (await client.transit_decrypt_data("foo", response_wrap))[
            "data"
        ]["plaintext"]
        assert plaintext_resp == "abbaabba"

    async def test_transit_generate_data_key(self):
        client = self.get_client()
        if "transit/" in (await client.list_secret_backends()):
            await client.disable_secret_backend("transit")
        await client.enable_secret_backend("transit")

        await client.transit_create_key("foo")

        response_plaintext = (
            await client.transit_generate_data_key("foo", key_type="plaintext")
        )["data"]["plaintext"]
        assert response_plaintext

        response_ciphertext = (
            await client.transit_generate_data_key("foo", key_type="wrapped")
        )["data"]
        assert "ciphertext" in response_ciphertext
        assert "plaintext" not in response_ciphertext

    async def test_transit_generate_rand_bytes(self):
        client = self.get_client()
        if "transit/" in (await client.list_secret_backends()):
            await client.disable_secret_backend("transit")
        await client.enable_secret_backend("transit")

        response_data = (await client.transit_generate_rand_bytes(data_bytes=4))[
            "data"
        ]["random_bytes"]
        assert response_data

    async def test_transit_hash_data(self):
        client = self.get_client()
        if "transit/" in (await client.list_secret_backends()):
            await client.disable_secret_backend("transit")
        await client.enable_secret_backend("transit")

        response_hash = (await client.transit_hash_data("abbaabba"))["data"]["sum"]
        assert len(response_hash) == 64

        response_hash = (
            await client.transit_hash_data("abbaabba", algorithm="sha2-512")
        )["data"]["sum"]
        assert len(response_hash) == 128

    async def test_transit_generate_verify_hmac(self):
        client = self.get_client()
        if "transit/" in (await client.list_secret_backends()):
            await client.disable_secret_backend("transit")
        await client.enable_secret_backend("transit")

        await client.transit_create_key("foo")

        response_hmac = (await client.transit_generate_hmac("foo", "abbaabba"))["data"][
            "hmac"
        ]
        assert response_hmac
        verify_resp = (
            await client.transit_verify_signed_data(
                "foo", "abbaabba", hmac=response_hmac
            )
        )["data"]["valid"]
        assert verify_resp

        response_hmac = (
            await client.transit_generate_hmac("foo", "abbaabba", algorithm="sha2-512")
        )["data"]["hmac"]
        assert response_hmac
        verify_resp = (
            await client.transit_verify_signed_data(
                "foo", "abbaabba", algorithm="sha2-512", hmac=response_hmac
            )
        )["data"]["valid"]
        assert verify_resp

    async def test_transit_sign_verify_signature_data(self):
        client = self.get_client()
        if "transit/" in (await client.list_secret_backends()):
            await client.disable_secret_backend("transit")
        await client.enable_secret_backend("transit")

        await client.transit_create_key("foo", key_type="ed25519")

        signed_resp = (await client.transit_sign_data("foo", "abbaabba"))["data"][
            "signature"
        ]
        assert signed_resp
        verify_resp = (
            await client.transit_verify_signed_data(
                "foo", "abbaabba", signature=signed_resp
            )
        )["data"]["valid"]
        assert verify_resp

        extra_kwargs = {}
        current_vault_version = util.get_vault_version()
        assert current_vault_version in ["1.16.3", "1.17.6", "1.18.5", "1.19.0"]
        if current_vault_version < "1.19.0":
            extra_kwargs = {"algorithm": "sha2-512"}
        signed_resp = (
            await client.transit_sign_data("foo", "abbaabba", **extra_kwargs)
        )["data"]["signature"]
        assert signed_resp
        verify_resp = (
            await client.transit_verify_signed_data(
                "foo", "abbaabba", signature=signed_resp, **extra_kwargs
            )
        )["data"]["valid"]
        assert verify_resp

    async def test_missing_token(self):
        client = create_client()
        assert not (await client.is_authenticated())
        await client.close()

    async def test_invalid_token(self):
        client = create_client(token="not-a-real-token")
        assert not (await client.is_authenticated())
        await client.close()

    async def test_illegal_token(self):
        client = create_client(token="token-with-new-line\n")
        try:
            await client.is_authenticated()
        except ValueError as e:
            assert "Newline or carriage return character" in str(e)
        await client.close()

    async def test_broken_token(self):
        client = create_client(token="\x1b")
        try:
            await client.is_authenticated()
        except exceptions.InvalidRequest as e:
            assert "invalid header value" in str(e)
        await client.close()

    async def test_client_authenticated(self):
        client = self.get_client()
        assert await client.is_authenticated()

    async def test_client_logout(self):
        client = self.get_client()
        client.logout()
        assert not (await client.is_authenticated())

    async def test_revoke_self_token(self):
        client = self.get_client()
        if "userpass/" in (await client.list_auth_backends()):
            await client.disable_auth_backend("userpass")

        await client.enable_auth_backend("userpass")

        await client.write(
            "auth/userpass/users/testuser", password="testpass", policies="not_root"
        )

        await client.auth_userpass("testuser", "testpass")

        await client.revoke_self_token()
        assert not (await client.is_authenticated())

    async def test_rekey_multi(self):
        cls = type(self)
        client = self.get_client()
        assert not (await client.rekey_status)["started"]

        await client.start_rekey()
        assert (await client.rekey_status)["started"]

        await client.cancel_rekey()
        assert not (await client.rekey_status)["started"]

        result = await client.start_rekey()

        keys = cls.manager.keys

        result = await client.rekey_multi(keys, nonce=result["nonce"])
        assert result["complete"]

        cls.manager.keys = result["keys"]
        cls.manager.unseal()

    async def test_rotate(self):
        client = self.get_client()
        status = await client.key_status

        await client.rotate()

        assert (await client.key_status)["term"] > status["term"]

    async def test_tls_auth(self):
        client = self.get_client()
        await client.enable_auth_backend("cert")

        with open("test-fixtures/client-cert.pem") as fp:
            certificate = fp.read()

        await client.write(
            "auth/cert/certs/test",
            display_name="test",
            policies="not_root",
            certificate=certificate,
        )

        await client.auth_tls()

    async def test_gh51(self):
        client = self.get_client()
        key = "secret/http://test.com"

        await client.write(key, foo="bar")

        result = await client.read(key)

        assert result["data"]["foo"] == "bar"

    async def test_token_accessor(self):
        client = self.get_client()
        # Create token, check accessor is provided
        result = await client.create_token(lease="1h")
        token_accessor = result["auth"].get("accessor", None)
        assert token_accessor

        # Look up token by accessor, make sure token is excluded from results
        lookup = await client.lookup_token(token_accessor, accessor=True)
        assert lookup["data"]["accessor"] == token_accessor
        assert not lookup["data"]["id"]

        # Revoke token using the accessor
        await client.revoke_token(token_accessor, accessor=True)

        # Look up by accessor should fail
        with self.assertRaises(exceptions.InvalidRequest):
            lookup = await client.lookup_token(token_accessor, accessor=True)

        # As should regular lookup
        with self.assertRaises(exceptions.Forbidden):
            lookup = await client.lookup_token(result["auth"]["client_token"])

    async def test_wrapped_token_success(self):
        client = self.get_client()
        wrap = await client.create_token(wrap_ttl="1m")

        # Unwrap token
        result = await client.unwrap(wrap["wrap_info"]["token"])
        assert result["auth"]["client_token"]

        # Validate token
        lookup = await client.lookup_token(result["auth"]["client_token"])
        assert result["auth"]["client_token"] == lookup["data"]["id"]

    async def test_wrapped_token_intercept(self):
        client = self.get_client()
        wrap = await client.create_token(wrap_ttl="1m")

        # Intercept wrapped token
        await client.unwrap(wrap["wrap_info"]["token"])

        # Attempt to retrieve the token after it's been intercepted
        with self.assertRaises(exceptions.InvalidRequest):
            await client.unwrap(wrap["wrap_info"]["token"])

    async def test_wrapped_token_cleanup(self):
        client = self.get_client()
        wrap = await client.create_token(wrap_ttl="1m")

        _token = client.token
        await client.unwrap(wrap["wrap_info"]["token"])
        assert client.token == _token

    async def test_wrapped_token_revoke(self):
        client = self.get_client()
        wrap = await client.create_token(wrap_ttl="1m")

        # Revoke token before it's unwrapped
        await client.revoke_token(wrap["wrap_info"]["wrapped_accessor"], accessor=True)

        # Unwrap token anyway
        result = await client.unwrap(wrap["wrap_info"]["token"])
        assert result["auth"]["client_token"]

        # Attempt to validate token
        with self.assertRaises(exceptions.Forbidden):
            await client.lookup_token(result["auth"]["client_token"])

    async def test_wrapped_client_token_success(self):
        client = self.get_client()
        wrap = await client.create_token(wrap_ttl="1m")
        client.token = wrap["wrap_info"]["token"]

        # Unwrap token
        result = await client.unwrap()
        assert result["auth"]["client_token"]

        # Validate token
        client.token = result["auth"]["client_token"]
        lookup = await client.lookup_token(result["auth"]["client_token"])
        assert result["auth"]["client_token"] == lookup["data"]["id"]

    async def test_wrapped_client_token_intercept(self):
        client = self.get_client()
        wrap = await client.create_token(wrap_ttl="1m")
        client.token = wrap["wrap_info"]["token"]

        # Intercept wrapped token
        await client.unwrap()

        # Attempt to retrieve the token after it's been intercepted
        with self.assertRaises(exceptions.InvalidRequest):
            await client.unwrap()

    async def test_wrapped_client_token_cleanup(self):
        client = self.get_client()
        wrap = await client.create_token(wrap_ttl="1m")

        _token = client.token
        client.token = wrap["wrap_info"]["token"]
        await client.unwrap()

        assert client.token != wrap
        assert client.token != _token

    async def test_wrapped_client_token_revoke(self):
        client = self.get_client()
        wrap = await client.create_token(wrap_ttl="1m")

        # Revoke token before it's unwrapped
        await client.revoke_token(wrap["wrap_info"]["wrapped_accessor"], accessor=True)

        # Unwrap token anyway
        client.token = wrap["wrap_info"]["token"]
        result = await client.unwrap()
        assert result["auth"]["client_token"]

        # Attempt to validate token
        with self.assertRaises(exceptions.Forbidden):
            await client.lookup_token(result["auth"]["client_token"])

    async def test_create_token_explicit_max_ttl(self):
        client = self.get_client()
        token = await client.create_token(ttl="30m", explicit_max_ttl="5m")

        assert token["auth"]["client_token"]

        assert token["auth"]["lease_duration"] == 300

        # Validate token
        lookup = await client.lookup_token(token["auth"]["client_token"])
        assert token["auth"]["client_token"] == lookup["data"]["id"]

    async def test_create_token_max_ttl(self):
        client = self.get_client()
        token = await client.create_token(ttl="5m")

        assert token["auth"]["client_token"]

        assert token["auth"]["lease_duration"] == 300

        # Validate token
        lookup = await client.lookup_token(token["auth"]["client_token"])
        assert token["auth"]["client_token"] == lookup["data"]["id"]

    async def test_create_token_periodic(self):
        client = self.get_client()
        token = await client.create_token(period="30m")

        assert token["auth"]["client_token"]

        assert token["auth"]["lease_duration"] == 1800

        # Validate token
        lookup = await client.lookup_token(token["auth"]["client_token"])
        assert token["auth"]["client_token"] == lookup["data"]["id"]
        assert lookup["data"]["period"] == 1800

    async def test_token_roles(self):
        client = self.get_client()
        # No roles, list_token_roles == None
        before = await client.list_token_roles()
        assert not before

        # Create token role
        assert (await client.create_token_role("testrole")).status == 204

        # List token roles
        during = (await client.list_token_roles())["data"]["keys"]
        assert len(during) == 1
        assert during[0] == "testrole"

        # Delete token role
        await client.delete_token_role("testrole")

        # No roles, list_token_roles == None
        after = await client.list_token_roles()
        assert not after

    async def test_create_token_w_role(self):
        client = self.get_client()
        # Create policy
        await self.prep_policy(client, "testpolicy")

        # Create token role w/ policy
        assert (
            await client.create_token_role("testrole", allowed_policies="testpolicy")
        ).status == 204

        # Create token against role
        token = await client.create_token(lease="1h", role="testrole")
        assert token["auth"]["client_token"]
        assert token["auth"]["policies"] == ["default", "testpolicy"]

        # Cleanup
        await client.delete_token_role("testrole")
        await client.delete_policy("testpolicy")

    async def test_ec2_role_crud(self):
        client = self.get_client()
        if "aws-ec2/" in (await client.list_auth_backends()):
            await client.disable_auth_backend("aws-ec2")
        await client.enable_auth_backend("aws-ec2")

        # create a policy to associate with the role
        await self.prep_policy(client, "ec2rolepolicy")

        # attempt to get a list of roles before any exist
        no_roles = await client.list_ec2_roles()
        # doing so should succeed and return None
        assert no_roles is None

        # test binding by AMI ID (the old way, to ensure backward compatibility)
        await client.create_ec2_role("foo", "ami-notarealami", policies="ec2rolepolicy")

        # test binding by Account ID
        await client.create_ec2_role(
            "bar", bound_account_id="123456789012", policies="ec2rolepolicy"
        )

        # test binding by IAM Role ARN
        await client.create_ec2_role(
            "baz",
            bound_iam_role_arn="arn:aws:iam::123456789012:role/mockec2role",
            policies="ec2rolepolicy",
        )

        # test binding by instance profile ARN
        await client.create_ec2_role(
            "qux",
            bound_iam_instance_profile_arn="arn:aws:iam::123456789012:instance-profile/mockprofile",
            policies="ec2rolepolicy",
        )

        # test binding by bound region
        await client.create_ec2_role(
            "quux", bound_region="ap-northeast-2", policies="ec2rolepolicy"
        )

        # test binding by bound vpc id
        await client.create_ec2_role(
            "corge", bound_vpc_id="vpc-1a123456", policies="ec2rolepolicy"
        )

        # test binding by bound subnet id
        await client.create_ec2_role(
            "grault", bound_subnet_id="subnet-123a456", policies="ec2rolepolicy"
        )

        roles = await client.list_ec2_roles()

        assert "foo" in roles["data"]["keys"]
        assert "bar" in roles["data"]["keys"]
        assert "baz" in roles["data"]["keys"]
        assert "qux" in roles["data"]["keys"]
        assert "quux" in roles["data"]["keys"]
        assert "corge" in roles["data"]["keys"]
        assert "grault" in roles["data"]["keys"]

        foo_role = await client.get_ec2_role("foo")
        assert "ami-notarealami" in foo_role["data"]["bound_ami_id"]
        assert "ec2rolepolicy" in foo_role["data"]["policies"]

        bar_role = await client.get_ec2_role("bar")
        assert "123456789012" in bar_role["data"]["bound_account_id"]
        assert "ec2rolepolicy" in bar_role["data"]["policies"]

        baz_role = await client.get_ec2_role("baz")
        assert (
            "arn:aws:iam::123456789012:role/mockec2role"
            in baz_role["data"]["bound_iam_role_arn"]
        )
        assert "ec2rolepolicy" in baz_role["data"]["policies"]

        qux_role = await client.get_ec2_role("qux")
        assert (
            "arn:aws:iam::123456789012:instance-profile/mockprofile"
            in qux_role["data"]["bound_iam_instance_profile_arn"]
        )
        assert "ec2rolepolicy" in qux_role["data"]["policies"]

        quux_role = await client.get_ec2_role("quux")
        assert "ap-northeast-2" in quux_role["data"]["bound_region"]
        assert "ec2rolepolicy" in quux_role["data"]["policies"]

        corge_role = await client.get_ec2_role("corge")
        assert "vpc-1a123456" in corge_role["data"]["bound_vpc_id"]
        assert "ec2rolepolicy" in corge_role["data"]["policies"]

        grault_role = await client.get_ec2_role("grault")
        assert "subnet-123a456" in grault_role["data"]["bound_subnet_id"]
        assert "ec2rolepolicy" in grault_role["data"]["policies"]

        # teardown
        await client.delete_ec2_role("foo")
        await client.delete_ec2_role("bar")
        await client.delete_ec2_role("baz")
        await client.delete_ec2_role("qux")
        await client.delete_ec2_role("quux")
        await client.delete_ec2_role("corge")
        await client.delete_ec2_role("grault")

        await client.delete_policy("ec2rolepolicy")

        await client.disable_auth_backend("aws-ec2")

    async def test_ec2_role_token_lifespan(self):
        client = self.get_client()
        if "aws-ec2/" not in (await client.list_auth_backends()):
            await client.enable_auth_backend("aws-ec2")

        # create a policy to associate with the role
        await self.prep_policy(client, "ec2rolepolicy")

        # create a role with no TTL
        await client.create_ec2_role("foo", "ami-notarealami", policies="ec2rolepolicy")

        # create a role with a 1hr TTL
        await client.create_ec2_role(
            "bar", "ami-notarealami", ttl="1h", policies="ec2rolepolicy"
        )

        # create a role with a 3-day max TTL
        await client.create_ec2_role(
            "baz", "ami-notarealami", max_ttl="72h", policies="ec2rolepolicy"
        )

        # create a role with 1-day period
        await client.create_ec2_role(
            "qux", "ami-notarealami", period="24h", policies="ec2rolepolicy"
        )

        foo_role = await client.get_ec2_role("foo")
        # Need to verify with older versions of vault
        # TODO if vault is < than ? use ttl else token_ttl
        assert foo_role["data"]["token_ttl"] == 0

        bar_role = await client.get_ec2_role("bar")
        assert bar_role["data"]["token_ttl"] == 3600

        baz_role = await client.get_ec2_role("baz")
        assert baz_role["data"]["max_ttl"] == 259200

        qux_role = await client.get_ec2_role("qux")
        assert qux_role["data"]["period"] == 86400

        # teardown
        await client.delete_ec2_role("foo")
        await client.delete_ec2_role("bar")
        await client.delete_ec2_role("baz")
        await client.delete_ec2_role("qux")

        await client.delete_policy("ec2rolepolicy")

        await client.disable_auth_backend("aws-ec2")

    def pad_base64(self, encoded_token):
        padding = len(encoded_token) % 4
        if padding != 0:
            encoded_token += "=" * (4 - padding)
        return encoded_token

    async def test_start_generate_root_with_completion(self):
        client = self.get_client()
        # TODO use older value for vault versions < = 1.9.0
        # test_otp = 'RSMGkAqBH5WnVLrDTbZ+UQ=='
        test_otp = "BMjzW3wAsEzINXCM05Wbas3u9zSl"

        self.assertFalse((await client.generate_root_status)["started"])
        response = await client.start_generate_root(
            key=test_otp,
            otp=True,
        )
        self.assertTrue((await client.generate_root_status)["started"])

        nonce = response["nonce"]
        for key in self.manager.keys[0:3]:
            response = await client.generate_root(
                key=key,
                nonce=nonce,
            )
        self.assertFalse((await client.generate_root_status)["started"])

        # Decode the token provided in the last response. Root token decoding logic derived from:
        # https://github.com/hashicorp/vault/blob/284600fbefc32d8ab71b6b9d1d226f2f83b56b1d/command/operator_generate_root.go#L289
        new_root_token = util.decode_generated_root_token(
            response["encoded_root_token"], test_otp
        )
        """
        padded_token = self.pad_base64(response['encoded_root_token'])
        b64decoded_root_token = b64decode(padded_token)
        xored = bytes(a ^ b for a, b in zip(b64decoded_root_token, test_otp.encode()))

        # Convert to string
        root_token = xored.decode('utf-8')        
        
        # b64decoded_root_token = b64decode(response['encoded_root_token'])

        if sys.version_info > (3, 0):
            # b64decoding + bytes XOR'ing to decode the new root token in python 3.x
            int_encoded_token = int.from_bytes(b64decoded_root_token, sys.byteorder)
            int_otp = int.from_bytes(b64decode(test_otp), sys.byteorder)
            xord_otp_and_token = int_otp ^ int_encoded_token
            token_hex_string = xord_otp_and_token.to_bytes(len(b64decoded_root_token), sys.byteorder).hex()
        else:
            # b64decoding + bytes XOR'ing to decode the new root token in python 2.7
            otp_and_token = zip(b64decode(test_otp), b64decoded_root_token)
            xord_otp_and_token = ''.join(chr(ord(y) ^ ord(x)) for (x, y) in otp_and_token)
            token_hex_string = binascii.hexlify(xord_otp_and_token)

        # new_root_token = str(UUID(token_hex_string))
        new_root_token = token_hex_string
        """
        # Assert our new root token is properly formed and authenticated
        client.token = new_root_token
        if await client.is_authenticated():
            self.root_token = new_root_token
        else:
            # If our new token was unable to authenticate, set the test client's token back to the original value
            client.token = self.root_token
            self.fail("Unable to authenticate with the newly generated root token.")

    async def test_start_generate_root_then_cancel(self):
        client = self.get_client()
        test_otp = "BMjzW3wAsEzINXCM05Wbas3u9zSl"

        self.assertFalse((await client.generate_root_status)["started"])
        await client.start_generate_root(
            key=test_otp,
            otp=True,
        )
        self.assertTrue((await client.generate_root_status)["started"])

        await client.cancel_generate_root()
        self.assertFalse((await client.generate_root_status)["started"])

    async def test_auth_ec2_alternate_mount_point_with_no_client_token_exception(self):
        client = self.get_client()
        test_mount_point = "aws-custom-path"
        # Turn on the aws-ec2 backend with a custom mount_point path specified.
        if "{0}/".format(test_mount_point) in (await client.list_auth_backends()):
            await client.disable_auth_backend(test_mount_point)
        await client.enable_auth_backend("aws-ec2", mount_point=test_mount_point)

        # Drop the client's token to replicate a typical end user's use of any auth method.
        # I.e., its reasonable to expect the method is being called to _retrieve_ a token in the first place.
        client.token = None

        # Load a mock PKCS7 encoded self-signed certificate to stand in for a real document from the AWS identity service.
        with open("test-fixtures/identity_document.p7b") as fp:
            pkcs7 = fp.read()

        # When attempting to auth (POST) to an auth backend mounted at a different path than the default, we expect a
        # generic 'missing client token' or permission denied response from Vault.
        with self.assertRaises(exceptions.Forbidden) as assertRaisesContext:
            await client.auth_ec2(pkcs7=pkcs7)

        expected_exception_message = "permission denied"
        actual_exception_message = str(assertRaisesContext.exception)
        self.assertEqual(expected_exception_message, actual_exception_message)

        # Reset test state.
        client.token = self.root_token()
        await client.disable_auth_backend(mount_point=test_mount_point)

    async def test_auth_ec2_alternate_mount_point_with_no_client_token(self):
        client = self.get_client()
        test_mount_point = "aws-custom-path"
        # Turn on the aws-ec2 backend with a custom mount_point path specified.
        if "{0}/".format(test_mount_point) in (await client.list_auth_backends()):
            await client.disable_auth_backend(test_mount_point)
        await client.enable_auth_backend("aws-ec2", mount_point=test_mount_point)

        # Drop the client's token to replicate a typical end user's use of any auth method.
        # I.e., its reasonable to expect the method is being called to _retrieve_ a token in the first place.
        client.token = None

        # Load a mock PKCS7 encoded self-signed certificate to stand in for a real document from the AWS identity service.
        with open("test-fixtures/identity_document.p7b") as fp:
            pkcs7 = fp.read()

        # If our custom path is respected, we'll still end up with Vault's inability to decrypt our dummy PKCS7 string.
        # However this exception indicates we're correctly hitting the expected auth endpoint.
        with self.assertRaises(exceptions.InternalServerError) as assertRaisesContext:
            await client.auth_ec2(pkcs7=pkcs7, mount_point=test_mount_point)

        expected_exception_message = "failed to decode the PEM encoded PKCS#7 signature"
        actual_exception_message = str(assertRaisesContext.exception)
        self.assertEqual(expected_exception_message, actual_exception_message)

        # Reset test state.
        client.token = self.root_token()
        await client.disable_auth_backend(mount_point=test_mount_point)

    async def test_auth_gcp_alternate_mount_point_with_no_client_token_exception(self):
        client = self.get_client()
        test_mount_point = "gcp-custom-path"
        # Turn on the gcp backend with a custom mount_point path specified.
        if "{0}/".format(test_mount_point) in (await client.list_auth_backends()):
            await client.disable_auth_backend(test_mount_point)
        await client.enable_auth_backend("gcp", mount_point=test_mount_point)

        # Drop the client's token to replicate a typical end user's use of any auth method.
        # I.e., its reasonable to expect the method is being called to _retrieve_ a token in the first place.
        client.token = None

        # Load a mock JWT stand in for a real document from GCP.
        with open("test-fixtures/example.jwt") as fp:
            jwt = fp.read()

        # When attempting to auth (POST) to an auth backend mounted at a different path than the default, we expect a
        # generic 'missing client token' or 'permission denied' response from Vault.
        # TODO this may work with vault version x but fails now
        with self.assertRaises(exceptions.Forbidden) as assertRaisesContext:
            await client.auth_gcp("example-role", jwt)

        expected_exception_message = "permission denied"
        actual_exception_message = str(assertRaisesContext.exception)
        self.assertEqual(expected_exception_message, actual_exception_message)

        # Reset test state.
        client.token = self.root_token()
        await client.disable_auth_backend(mount_point=test_mount_point)

    async def test_tune_auth_backend(self):
        client = self.get_client()
        test_backend_type = "approle"
        test_mount_point = "tune-approle"
        test_description = "this is a test auth backend"
        test_max_lease_ttl = 12345678
        if "{0}/".format(test_mount_point) in (await client.list_auth_backends()):
            await client.disable_auth_backend(test_mount_point)
        await client.enable_auth_backend(
            backend_type="approle", mount_point=test_mount_point
        )

        expected_status_code = 204
        response = await client.tune_auth_backend(
            backend_type=test_backend_type,
            mount_point=test_mount_point,
            description=test_description,
            max_lease_ttl=test_max_lease_ttl,
        )
        self.assertEqual(
            first=expected_status_code,
            second=response.status,
        )

        response = await client.get_auth_backend_tuning(
            backend_type=test_backend_type, mount_point=test_mount_point
        )

        self.assertEqual(
            first=test_max_lease_ttl, second=response["data"]["max_lease_ttl"]
        )

        await client.disable_auth_backend(mount_point=test_mount_point)

    async def test_create_kubernetes_configuration(self):
        client = self.get_client()
        expected_status_code = 204
        test_mount_point = "k8s"

        # Turn on the kubernetes backend with a custom mount_point path specified.
        if "{0}/".format(test_mount_point) in (await client.list_auth_backends()):
            await client.disable_auth_backend(test_mount_point)
        await client.enable_auth_backend("kubernetes", mount_point=test_mount_point)

        with open("test-fixtures/client-cert.pem") as fp:
            certificate = fp.read()
            response = await client.create_kubernetes_configuration(
                kubernetes_host="127.0.0.1:80",
                pem_keys=[certificate],
                mount_point=test_mount_point,
                kubernetes_ca_cert="test-fixtures/ca.crt",
            )
        self.assertEqual(
            first=expected_status_code,
            second=response.status,
        )

        # Reset integration test state
        await client.disable_auth_backend(mount_point=test_mount_point)

    async def test_get_kubernetes_configuration(self):
        client = self.get_client()
        test_host = "127.0.0.1:80"
        # test_mount_point = 'k8s'
        test_mount_point = "kubernetes"

        # Turn on the kubernetes backend with a custom mount_point path specified.
        if "{0}/".format(test_mount_point) in (await client.list_auth_backends()):
            await client.disable_auth_backend(test_mount_point)
        await client.enable_auth_backend("kubernetes", mount_point=test_mount_point)
        with open("test-fixtures/client-cert.pem") as fp:
            certificate = fp.read()
            await client.create_kubernetes_configuration(
                kubernetes_host=test_host,
                pem_keys=[certificate],
                mount_point=test_mount_point,
                kubernetes_ca_cert="test-fixtures/ca.crt",
            )

        # Test that we can retrieve the configuration
        response = await client.get_kubernetes_configuration(
            mount_point=test_mount_point
        )
        self.assertIn(
            member="data",
            container=response,
        )
        self.assertEqual(
            first=test_host, second=response["data"].get("kubernetes_host")
        )

        # Reset integration test state
        await client.disable_auth_backend(mount_point=test_mount_point)

    async def test_create_kubernetes_role(self):
        client = self.get_client()
        test_role_name = "test_role"
        test_mount_point = "k8s"
        expected_status_code = 204

        # Turn on the kubernetes backend with a custom mount_point path specified.
        if "{0}/".format(test_mount_point) in (await client.list_auth_backends()):
            await client.disable_auth_backend(test_mount_point)
        await client.enable_auth_backend("kubernetes", mount_point=test_mount_point)

        with open("test-fixtures/client-cert.pem") as fp:
            certificate = fp.read()
            await client.create_kubernetes_configuration(
                kubernetes_host="127.0.0.1:80",
                pem_keys=[certificate],
                mount_point=test_mount_point,
                kubernetes_ca_cert="test-fixtures/ca.crt",
            )

        # Test that we can createa role
        response = await client.create_kubernetes_role(
            name=test_role_name,
            bound_service_account_names="*",
            bound_service_account_namespaces="vault_test",
            mount_point=test_mount_point,
        )
        self.assertEqual(
            first=expected_status_code,
            second=response.status,
        )

        # Reset integration test state
        await client.disable_auth_backend(mount_point=test_mount_point)

    async def test_get_kubernetes_role(self):
        client = self.get_client()
        test_role_name = "test_role"
        test_mount_point = "k8s"
        test_bound_service_account_namespaces = ["vault-test"]

        # Turn on the kubernetes backend with a custom mount_point path specified.
        if "{0}/".format(test_mount_point) in (await client.list_auth_backends()):
            await client.disable_auth_backend(test_mount_point)
        await client.enable_auth_backend("kubernetes", mount_point=test_mount_point)

        with open("test-fixtures/client-cert.pem") as fp:
            certificate = fp.read()
            await client.create_kubernetes_configuration(
                kubernetes_host="127.0.0.1:80",
                pem_keys=[certificate],
                mount_point=test_mount_point,
                kubernetes_ca_cert="test-fixtures/ca.crt",
            )

        # Test that we can createa role
        await client.create_kubernetes_role(
            name=test_role_name,
            bound_service_account_names="*",
            bound_service_account_namespaces=test_bound_service_account_namespaces,
            mount_point=test_mount_point,
        )
        response = await client.get_kubernetes_role(
            name=test_role_name,
            mount_point=test_mount_point,
        )
        self.assertIn(
            member="data",
            container=response,
        )
        self.assertEqual(
            first=test_bound_service_account_namespaces,
            second=response["data"].get("bound_service_account_namespaces"),
        )
        # Reset integration test state
        await client.disable_auth_backend(mount_point=test_mount_point)

    async def test_list_kubernetes_roles(self):
        client = self.get_client()
        test_role_name = "test_role"
        test_mount_point = "k8s"
        test_bound_service_account_namespaces = ["vault-test"]

        # Turn on the kubernetes backend with a custom mount_point path specified.
        if "{0}/".format(test_mount_point) in (await client.list_auth_backends()):
            await client.disable_auth_backend(test_mount_point)
        await client.enable_auth_backend("kubernetes", mount_point=test_mount_point)

        with open("test-fixtures/client-cert.pem") as fp:
            certificate = fp.read()
            await client.create_kubernetes_configuration(
                kubernetes_host="127.0.0.1:80",
                pem_keys=[certificate],
                mount_point=test_mount_point,
                kubernetes_ca_cert="test-fixtures/ca.crt",
            )

        # Test that we can createa role
        await client.create_kubernetes_role(
            name=test_role_name,
            bound_service_account_names="*",
            bound_service_account_namespaces=test_bound_service_account_namespaces,
            mount_point=test_mount_point,
        )
        response = await client.list_kubernetes_roles(
            mount_point=test_mount_point,
        )
        self.assertIn(
            member="data",
            container=response,
        )
        self.assertEqual(first=[test_role_name], second=response["data"].get("keys"))
        # Reset integration test state
        await client.disable_auth_backend(mount_point=test_mount_point)

    async def test_delete_kubernetes_role(self):
        client = self.get_client()
        test_role_name = "test_role"
        test_mount_point = "k8s"
        expected_status_code = 204

        # Turn on the kubernetes backend with a custom mount_point path specified.
        if "{0}/".format(test_mount_point) in (await client.list_auth_backends()):
            await client.disable_auth_backend(test_mount_point)
        await client.enable_auth_backend("kubernetes", mount_point=test_mount_point)

        with open("test-fixtures/client-cert.pem") as fp:
            certificate = fp.read()
            await client.create_kubernetes_configuration(
                kubernetes_host="127.0.0.1:80",
                pem_keys=[certificate],
                mount_point=test_mount_point,
                kubernetes_ca_cert="test-fixtures/ca.crt",
            )

        await client.create_kubernetes_role(
            name=test_role_name,
            bound_service_account_names="*",
            bound_service_account_namespaces="vault_test",
            mount_point=test_mount_point,
        )
        # Test that we can delete a role
        response = await client.delete_kubernetes_role(
            role=test_role_name,
            mount_point=test_mount_point,
        )
        self.assertEqual(
            first=expected_status_code,
            second=response.status,
        )

        # Reset integration test state
        await client.disable_auth_backend(mount_point=test_mount_point)

    async def test_auth_kubernetes(self):
        client = self.get_client()
        test_role_name = "test_role"
        test_host = "127.0.0.1:80"
        test_mount_point = "k8s"

        # Turn on the kubernetes backend with a custom mount_point path specified.
        if "{0}/".format(test_mount_point) in (await client.list_auth_backends()):
            await client.disable_auth_backend(test_mount_point)
        await client.enable_auth_backend("kubernetes", mount_point=test_mount_point)
        with open("test-fixtures/client-cert.pem") as fp:
            certificate = fp.read()
            await client.create_kubernetes_configuration(
                kubernetes_host=test_host,
                pem_keys=[certificate],
                mount_point=test_mount_point,
                kubernetes_ca_cert="test-fixtures/ca.crt",
            )

        await client.create_kubernetes_role(
            name=test_role_name,
            bound_service_account_names="*",
            bound_service_account_namespaces="vault_test",
            mount_point=test_mount_point,
        )

        # Test that we can authenticate
        with open("test-fixtures/example.jwt") as fp:
            test_jwt = fp.read()
            # TODO on previous verisons of vault this will be InternalServerError but now it is Forbidden
            with self.assertRaises(exceptions.Forbidden) as assertRaisesContext:
                # we don't actually have a valid JWT to provide, so this method will throw an exception
                await client.auth_kubernetes(
                    role=test_role_name,
                    jwt=test_jwt,
                    mount_point=test_mount_point,
                )
        # TOD see above
        expected_exception_message = "permission denied"
        actual_exception_message = str(assertRaisesContext.exception)
        self.assertEqual(expected_exception_message, actual_exception_message)

        # Reset integration test state
        await client.disable_auth_backend(mount_point=test_mount_point)
