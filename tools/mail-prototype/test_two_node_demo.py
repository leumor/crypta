"""Offline validation of the opt-in driver; fixtures never establish live delivery."""
import contextlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

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

    def test_callable_private_bodies_and_scan_hook_preserve_original_protocol_flow(self):
        alice, bob = Mock(), Mock()
        alice.command.side_effect = [
            {"status": "initialize-required"}, {}, {"card": "alice-card"},
            {"status": "wrong-recipient"}, {"status": "accepted", "messageId": "reply-id"},
            {"body": "private-reply"}]
        bob.command.side_effect = [
            {"status": "initialize-required"}, {}, {"card": "bob-card"},
            {"status": "accepted", "messageId": "body-id"},
            {"status": "verified-local-copy", "body": "private-body"}, {"status": "duplicate"}]
        observed = []
        bob.restart.side_effect = lambda: observed.append("restart")
        with patch.object(demo, "pin", side_effect=["bob-pin", "alice-pin"]), patch.object(demo, "send", side_effect=["first-ref", "reply-ref"]) as send:
            result = demo.run_flow(alice, bob, 30, True, body="private-body", reply_body="private-reply",
                                   before_restart=lambda: observed.append("scan"))
        self.assertEqual(["scan", "restart"], observed)
        self.assertEqual("private-body", send.call_args_list[0].args[2])
        self.assertEqual("private-reply", send.call_args_list[1].args[2])
        self.assertEqual("observed-demo", result["overall"])
        self.assertNotIn("private-body", str(result))

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
