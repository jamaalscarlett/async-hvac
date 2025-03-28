from async_hvac import AsyncClient
from async_hvac.tests.util import RequestsMocker
from unittest import IsolatedAsyncioTestCase
from parameterized import parameterized


class TestClient(IsolatedAsyncioTestCase):
    """Unit tests providing coverage for requests-related methods in the hvac Client class."""

    @parameterized.expand(
        [
            ("standard Vault address", "https://localhost:8200"),
            ("Vault address with route", "https://example.com/vault"),
        ]
    )
    @RequestsMocker()
    async def test___request(self, test_label, test_url, requests_mocker):
        test_path = "v1/sys/health"
        expected_status_code = 200
        mock_url = "{0}/{1}".format(test_url, test_path)
        requests_mocker.register_uri(
            method="GET",
            url=mock_url,
        )
        client = AsyncClient(url=test_url)
        response = await client._get(
            url="v1/sys/health",
        )
        self.assertEqual(
            first=expected_status_code,
            second=response.status,
        )
        await client.close()

    @parameterized.expand(
        [
            ("standard Vault address", "https://localhost:8200"),
            ("Vault address with route", "https://example.com/vault"),
        ]
    )
    @RequestsMocker()
    async def test_async_with_request(self, test_label, test_url, requests_mocker):
        test_path = "v1/sys/health"
        expected_status_code = 200
        mock_url = "{0}/{1}".format(test_url, test_path)
        requests_mocker.register_uri(
            method="GET",
            url=mock_url,
        )
        async with AsyncClient(url=test_url) as client:
            response = await client._get(
                url="v1/sys/health",
            )
            self.assertEqual(
                first=expected_status_code,
                second=response.status,
            )
