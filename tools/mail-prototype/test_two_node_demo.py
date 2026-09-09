"""Offline validation of the opt-in driver; fixtures never establish live delivery."""
import contextlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("mail_demo", Path(__file__).with_name("two_node_demo.py"))
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


class DemoTest(unittest.TestCase):
    def test_targets_reject_remote_redirect_credentials_and_paths(self):
        for value in ("https://127.0.0.1:8888/api/v1", "http://example.com:8888/api/v1",
                      "http://127.0.0.1/api/v1", "http://u:p@127.0.0.1:8888/api/v1",
                      "http://127.0.0.1:8888/api/v1?secret=x", "http://127.0.0.1:8888/other"):
            with self.assertRaises(demo.DemoFailure):
                demo.target(value, True)
        self.assertEqual("http://127.0.0.1:8888/api/v1", demo.target("http://127.0.0.1:8888/api/v1", True))

    def test_missing_opt_in_never_constructs_http_client(self):
        args = ["--alice-api", "http://127.0.0.1:8888/api/v1", "--bob-api", "http://127.0.0.1:8889/api/v1",
                "--alice-origin", "http://127.0.0.1:9000", "--bob-origin", "http://127.0.0.1:9001"]
        with patch.object(demo, "Client") as client, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(1, demo.main(args))
            client.assert_not_called()
            self.assertNotIn("127.0.0.1", output.getvalue())

    def test_fixture_client_uses_session_origin_and_bounded_command_results(self):
        client = demo.Client("http://127.0.0.1:8888/api/v1", "http://127.0.0.1:9000", "synthetic-session")
        value = demo.base64.b64encode(b'{"status":"fixture-only"}').decode()
        with patch.object(client, "post", side_effect=[{"mail": {"requestId": "synthetic-id"}},
                                                       {"mail": {"status": "complete", "payloadBase64": value}}]) as post:
            self.assertEqual({"status": "fixture-only"}, client.command("status"))
            self.assertEqual("/mail/command", post.call_args_list[0].args[0])
            self.assertEqual("/mail/result", post.call_args_list[1].args[0])

    def test_existing_mailbox_aborts_before_initialization(self):
        class Fixture:
            calls = []
            def command(self, command, payload=None):
                self.calls.append(command)
                return {"status": "initialized"}
        client = Fixture()
        with self.assertRaises(demo.DemoFailure):
            demo.run_flow(client, client, 30, False)
        self.assertEqual(["status"], client.calls)


if __name__ == "__main__":
    unittest.main()
