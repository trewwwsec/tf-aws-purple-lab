import os
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from config_loader import enforce_security_posture, load_settings


class TestConfigSecurity(unittest.TestCase):
    def test_enforce_security_strict_rejects_insecure_flags(self):
        settings = {
            "wazuh": {"ssl_verify": False},
            "rag": {"enabled": True, "opensearch": {"use_ssl": True, "verify_certs": False}},
            "api": {"require_auth": False},
        }
        with self.assertRaises(ValueError):
            enforce_security_posture(settings, runtime_mode="strict")

    def test_enforce_security_demo_warns(self):
        settings = {
            "wazuh": {"ssl_verify": False},
            "rag": {"enabled": True, "opensearch": {"use_ssl": False, "verify_certs": False}},
            "api": {"require_auth": False},
        }
        warnings = enforce_security_posture(settings, runtime_mode="demo")
        self.assertTrue(warnings)
        self.assertTrue(any("wazuh.ssl_verify" in warning for warning in warnings))

    def test_env_secret_resolution(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tmp:
            tmp.write(
                textwrap.dedent(
                    """
                    wazuh:
                      password_env: TEST_WAZUH_SECRET
                    """
                )
            )
            path = tmp.name

        try:
            os.environ["TEST_WAZUH_SECRET"] = "super-secret-value"
            settings = load_settings(path)
            self.assertEqual(settings["wazuh"]["password"], "super-secret-value")
        finally:
            os.environ.pop("TEST_WAZUH_SECRET", None)
            os.unlink(path)

    def test_plaintext_secret_detected(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tmp:
            tmp.write(
                textwrap.dedent(
                    """
                    api:
                      auth_token: "hard-coded-token"
                    """
                )
            )
            path = tmp.name

        try:
            settings = load_settings(path)
            with self.assertRaises(ValueError):
                enforce_security_posture(settings, runtime_mode="strict")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
