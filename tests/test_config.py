"""Configuration defaults and secret sources."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from dataclasses import asdict

from cornicen.config import load_config


class ConfigTests(unittest.TestCase):
    def load(self, text="", env=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text(text)
            return load_config(path, {} if env is None else env)

    def test_defaults(self):
        config = self.load()
        self.assertEqual(config.epss_threshold, 0.10)
        self.assertEqual(config.digest_time, "08:00")
        self.assertEqual(config.timezone, "UTC")
        self.assertEqual(config.overdue_minutes, 60)
        self.assertEqual(config.retention_days, 365)
        self.assertIsNone(config.ntfy_token)
        self.assertIsNone(config.aliases_path)
        self.assertEqual(config.user_agent_overrides, {})
        self.assertEqual(config.user_agent,
                         "Cornicen/0.1.13 (+https://github.com/<owner>/cornicen)")

    def test_overrides(self):
        config = self.load('''db_path = "state.db"
watchlist_path = "watch.toml"
aliases_path = "aliases.toml"
ntfy_url = "https://ntfy.invalid"
ntfy_topic = "example"
epss_threshold = 0.2
digest_time = "09:30"
timezone = "America/New_York"
overdue_minutes = 90
retention_days = 30
owner = "examplecorp"
[user_agent_overrides]
"example.invalid" = "Example agent"
''')
        self.assertEqual(Path(config.db_path), Path("state.db"))
        self.assertEqual(config.watchlist_path, Path("watch.toml"))
        self.assertEqual(config.aliases_path, Path("aliases.toml"))
        self.assertEqual(config.ntfy_url, "https://ntfy.invalid")
        self.assertEqual(config.ntfy_topic, "example")
        self.assertEqual(config.epss_threshold, 0.2)
        self.assertEqual(config.digest_time, "09:30")
        self.assertEqual(config.timezone, "America/New_York")
        self.assertEqual(config.overdue_minutes, 90)
        self.assertEqual(config.retention_days, 30)
        self.assertIn("/examplecorp/cornicen", config.user_agent)
        self.assertEqual(config.user_agent_overrides, {"example.invalid": "Example agent"})

    def test_explicit_user_agent(self):
        self.assertEqual(self.load('user_agent = "Example/1"').user_agent, "Example/1")

    def test_token_in_toml_rejected(self):
        with self.assertRaisesRegex(ValueError, "CORNICEN_NTFY_TOKEN") as caught:
            self.load('ntfy_token = "fixture-secret"')
        self.assertNotIn("fixture-secret", str(caught.exception))

    def test_token_from_environment_and_not_repr(self):
        config = self.load(env={"CORNICEN_NTFY_TOKEN": "fixture-secret"})
        self.assertEqual(config.ntfy_token.reveal(), "fixture-secret")
        self.assertNotIn("fixture-secret", repr(config))

    def test_token_from_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            path.write_text("fixture-secret\n")
            path.chmod(0o600)
            config = self.load(env={"CORNICEN_NTFY_TOKEN_FILE": str(path)})
        self.assertEqual(config.ntfy_token.reveal(), "fixture-secret")

    def test_environment_token_takes_precedence(self):
        config = self.load(env={"CORNICEN_NTFY_TOKEN": "fixture-secret",
                                "CORNICEN_NTFY_TOKEN_FILE": "does-not-exist"})
        self.assertEqual(config.ntfy_token.reveal(), "fixture-secret")

    def test_invalid_settings(self):
        for text in ('epss_threshold = 1.1', 'epss_threshold = -0.1',
                     'epss_threshold = nan', 'digest_time = "25:00"',
                     'overdue_minutes = 0', 'retention_days = -1',
                     'overdue_minutes = true', 'timezone = "Invalid/Zone"',
                     'watchlist_path = 3', 'user_agent_overrides = []'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.load(text)

    def test_token_is_stripped_validated_and_redacted(self):
        for from_file in (False, True):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "token"
                for value in ("  fixture-secret\n", "bad token", "bad\ttoken", "bad\x00token", "bad\x7ftoken", "bad\x85token"):
                    path.write_text(value)
                    path.chmod(0o600)
                    env = ({"CORNICEN_NTFY_TOKEN_FILE": str(path)} if from_file else
                           {"CORNICEN_NTFY_TOKEN": value})
                    with self.subTest(from_file=from_file, value=value):
                        if value.startswith("  "):
                            config = self.load(env=env)
                            self.assertEqual(config.ntfy_token.reveal(), "fixture-secret")
                            self.assertEqual(str(config.ntfy_token), "***")
                            self.assertEqual(repr(config.ntfy_token), "***")
                            for data in (config, asdict(config), vars(config), vars(config.ntfy_token)
                                         if hasattr(config.ntfy_token, "__dict__") else {}):
                                self.assertNotIn("fixture-secret", repr(data))
                        else:
                            with self.assertRaises(ValueError) as caught:
                                self.load(env=env)
                            self.assertNotIn(value, str(caught.exception))

    def test_unknown_and_nested_secret_settings(self):
        for text in ('typo = "oops"', '[ntfy]\ntopic = "oops"'):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "unknown"):
                self.load(text)
        for text in ('TOKEN = "fixture-secret"', 'api_secret = "fixture-secret"',
                     '[nested.deeper]\npassword = "fixture-secret"',
                     '[user_agent_overrides]\nsecret_host = "fixture-secret"',
                     'nested = [{ credentials = { access_token = "fixture-secret" } }]'):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "use CORNICEN_NTFY_TOKEN") as caught:
                self.load(text)
            self.assertNotIn("fixture-secret", str(caught.exception))

    def test_url_and_header_settings_are_validated(self):
        for url in ("ftp://ntfy.invalid", "https://user:pass@ntfy.invalid", "https:///missing", "https://"):
            with self.subTest(url=url), self.assertRaisesRegex(ValueError, "ntfy_url"):
                self.load(f'ntfy_url = "{url}"')
        for text in ('user_agent = "bad\\nagent"', 'owner = "bad\\towner"',
                     '[user_agent_overrides]\n"host" = "bad\\u007Fagent"',
                     '[user_agent_overrides]\n"bad\\n host" = "agent"', 'owner = "bad\\u0085owner"'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.load(text)
        self.assertEqual(self.load('ntfy_url = "http://localhost:8080"').ntfy_url, "http://localhost:8080")

    def test_recursive_config_toml_is_rejected(self):
        with patch("cornicen.config.tomllib.load", side_effect=RecursionError):
            with self.assertRaises(ValueError):
                self.load()
