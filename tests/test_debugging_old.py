from tests.test_client import CFMSTestClient


class TestDebuggingOperations:
    """Test debugging operations."""

    def test_throw_exception(self, authenticated_client: CFMSTestClient):
        """Test the throw_exception debugging request."""
        response = authenticated_client.send_request(
            "throw_exception",
            {},
        )

        assert response["code"] == 500
