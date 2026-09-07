#!/usr/bin/env python3
"""Explicit live Mail demonstration. Never emits private response bodies or target metadata."""
import argparse
import base64
import json
import os
import time
import urllib.parse
import urllib.request

BODY = "PUBLIC SYNTHETIC CRYPTA MAIL PROTOTYPE DEMONSTRATION"
REPLY = "PUBLIC SYNTHETIC CRYPTA MAIL PROTOTYPE REPLY"


class DemoFailure(Exception):
    """Bounded failure without private details."""


def target(value, api=False):
    """Accept only canonical literal-loopback targets with explicit ports."""
    try:
        parsed = urllib.parse.urlsplit(value)
        if (parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "::1")
                or parsed.port is None or not 1 <= parsed.port <= 65535
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment
                or parsed.path != ("/api/v1" if api else "")):
            raise DemoFailure()
        if any(c.isspace() for c in value):
            raise DemoFailure()
        return value
    except (ValueError, TypeError):
        raise DemoFailure() from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DemoFailure()


class Client:
    def __init__(self, api, origin, session, password=None):
        self.api = target(api, True)
        self.origin = target(origin)
        if not session or len(session) > 4096 or any(c in session for c in "\r\n"):
            raise DemoFailure()
        self.session = session
        self.password = password
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def post(self, path, parameters, host=False):
        if path not in ("/mail/command", "/mail/result", "/apps/mail-prototype/stop", "/apps/mail-prototype/start"):
            raise DemoFailure()
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        values = dict(parameters)
        if host:
            if not self.password:
                raise DemoFailure()
            values["formPassword"] = self.password
        else:
            headers.update({"Origin": self.origin, "X-Crypta-App-Session": self.session})
        encoded = urllib.parse.urlencode(values).encode("ascii")
        if len(encoded) > 786432:
            raise DemoFailure()
        request = urllib.request.Request(self.api + path, data=encoded, headers=headers, method="POST")
        try:
            with self.opener.open(request, timeout=25) as response:
                raw = response.read(1048577)
                if len(raw) > 1048576:
                    raise DemoFailure()
                result = json.loads(raw.decode("utf-8"))
                if not isinstance(result, dict):
                    raise DemoFailure()
                return result
        except Exception:
            raise DemoFailure() from None

    def command(self, command, payload=None):
        raw = json.dumps(payload or {}, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        submitted = self.post("/mail/command", {"command": command, "payloadBase64": base64.b64encode(raw).decode("ascii")})
        request_id = submitted["mail"]["requestId"]
        deadline = time.monotonic() + 28
        while time.monotonic() < deadline:
            result = self.post("/mail/result", {"requestId": request_id})["mail"]
            if result.get("status") == "complete":
                encoded = result.get("payloadBase64", "")
                if len(encoded) > 393216:
                    raise DemoFailure()
                decoded = json.loads(base64.b64decode(encoded, validate=True).decode("utf-8"))
                if not isinstance(decoded, dict):
                    raise DemoFailure()
                return decoded
            if result.get("status") != "pending":
                raise DemoFailure()
            time.sleep(0.2)
        raise DemoFailure()

    def restart(self):
        self.post("/apps/mail-prototype/stop", {}, host=True)
        self.post("/apps/mail-prototype/start", {}, host=True)
        # Browser sessions bind the installed bundle/origin, not the terminated process token.
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            try:
                self.command("status")
                return
            except DemoFailure:
                time.sleep(0.25)
        raise DemoFailure()


def expect(result, status):
    if result.get("status") != status:
        raise DemoFailure()
    return result


def pin(receiver, card):
    inspected = expect(receiver.command("import-contact", {"card": card}), "compare-fingerprint-out-of-band")
    fingerprint = inspected["fingerprint"]
    expect(receiver.command("approve-contact", {"fingerprint": fingerprint}), "contact-approved")
    return fingerprint


def send(sender, fingerprint, body, timeout):
    expect(sender.command("save-draft", {"fingerprint": fingerprint, "subject": "Public synthetic demo", "body": body}), "draft")
    preview = expect(sender.command("preview-send"), "approval-required")
    if preview.get("body") != body:
        raise DemoFailure()
    queued = expect(sender.command("confirm-send", {"approval": preview["approval"]}), "queued")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = sender.command("retry", {"operation": queued["operation"]})
        if result.get("status") == "inserted":
            reference = result.get("reference", "")
            if not reference.startswith("CHK@") or len(reference) > 512:
                raise DemoFailure()
            return reference
        expect(result, "queued")
        time.sleep(2)
    raise DemoFailure()


def run_flow(alice, bob, timeout, restart):
    # Check both before either initialization: a pre-existing dataset aborts all mutation.
    expect(alice.command("status"), "initialize-required")
    expect(bob.command("status"), "initialize-required")
    alice.command("initialize")
    bob.command("initialize")
    a_card = alice.command("export-contact")["card"]
    b_card = bob.command("export-contact")["card"]
    if a_card == b_card:
        raise DemoFailure()
    b_pin = pin(alice, b_card)
    a_pin = pin(bob, a_card)
    reference = send(alice, b_pin, BODY, timeout)
    imported = expect(bob.command("import-reference", {"reference": reference, "confirmed": "yes"}), "accepted")
    read = expect(bob.command("read", {"messageId": imported["messageId"]}), "verified-local-copy")
    if read.get("body") != BODY:
        raise DemoFailure()
    wrong = alice.command("import-reference", {"reference": reference, "confirmed": "yes"})
    expect(wrong, "wrong-recipient")
    if restart:
        bob.restart()
    expect(bob.command("import-reference", {"reference": reference, "confirmed": "yes"}), "duplicate")
    reply_ref = send(bob, a_pin, REPLY, timeout)
    reply = expect(alice.command("import-reference", {"reference": reply_ref, "confirmed": "yes"}), "accepted")
    if alice.command("read", {"messageId": reply["messageId"]}).get("body") != REPLY:
        raise DemoFailure()
    return {"insertFetchDecrypt": "observed", "wrongRecipient": "observed", "duplicate": "observed",
            "reply": "observed", "restart": "observed" if restart else "skipped",
            "independentStoresAndSignedInstalls": "operator-attested",
            "securityReview": "unobserved", "releaseEligible": False,
            "overall": "observed-demo" if restart else "incomplete"}


class PrivateParser(argparse.ArgumentParser):
    def error(self, message):
        raise DemoFailure()


def parser():
    result = PrivateParser(description=__doc__)
    result.add_argument("--alice-api", required=True)
    result.add_argument("--bob-api", required=True)
    result.add_argument("--alice-origin", required=True)
    result.add_argument("--bob-origin", required=True)
    result.add_argument("--execute", action="store_true")
    result.add_argument("--disposable-targets", action="store_true")
    result.add_argument("--independent-vaults-signed-installs", action="store_true")
    result.add_argument("--restart-recipient", action="store_true")
    result.add_argument("--insert-timeout-seconds", type=int, default=600)
    return result


def validate_options(args):
    if not (args.execute and args.disposable_targets and args.independent_vaults_signed_installs):
        raise DemoFailure()
    apis = [target(args.alice_api, True), target(args.bob_api, True)]
    origins = [target(args.alice_origin), target(args.bob_origin)]
    if len(set(apis + origins)) != 4 or not 30 <= args.insert_timeout_seconds <= 1800:
        raise DemoFailure()
    authorities = [urllib.parse.urlsplit(value).netloc for value in apis + origins]
    if len(set(authorities)) != 4 or len({urllib.parse.urlsplit(value).port for value in apis + origins}) != 4:
        raise DemoFailure()


def main(argv=None):
    try:
        args = parser().parse_args(argv)
        validate_options(args)
        password = os.environ.get("CRYPTAD_MAIL_DEMO_BOB_FORM_PASSWORD")
        if args.restart_recipient and not password:
            raise DemoFailure()
        alice = Client(args.alice_api, args.alice_origin, os.environ.get("CRYPTAD_MAIL_DEMO_ALICE_SESSION"))
        bob = Client(args.bob_api, args.bob_origin, os.environ.get("CRYPTAD_MAIL_DEMO_BOB_SESSION"), password)
        summary = run_flow(alice, bob, args.insert_timeout_seconds, args.restart_recipient)
        print(json.dumps(summary, sort_keys=True))
        return 0 if summary["overall"] == "observed-demo" else 2
    except Exception:
        print('{"overall":"failed","privateDetails":"withheld","releaseEligible":false}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
