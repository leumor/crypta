# Explicit two-node Mail demonstration

`two_node_demo.py` performs real ciphertext insert/fetch only after explicit execution and disposable
target acknowledgments. It is not a self-test or certification producer. It never installs an app,
cleans existing data, changes node configuration or prints private response bodies/references.

The [cross-version supervisor](../../docs/cross-version-live-network-soak.md) reuses this callable
flow after provisioning its own selected signed installations and acquiring normal own-app
sessions. That adapter's process/store observations are separate from this standalone command's
operator attestation. Missing protected authentication and unexecuted Mail cases remain explicit;
neither path supplies independent security review or a restore-resume operation.

Prepare two independent disposable node installations, stores and vaults. Install and start the
signed experimental Mail bundle on each through normal AppHost verification. Leave both Mail
accounts uninitialized. The command checks both accounts report `initialize-required` before either
initialization; retained/lost-key or existing-data conditions fail closed. Distinct URLs alone do
not prove independent stores or signed-install verification: the operator explicitly attests them.
Do not point this command at pre-existing personal nodes.

Obtain a fresh own-origin Mail browser session for each installed app through its ordinary bootstrap
flow. Put session values in `CRYPTAD_MAIL_DEMO_ALICE_SESSION` and
`CRYPTAD_MAIL_DEMO_BOB_SESSION` using a private environment/secret mechanism. Never pass credentials
on the command line or save them in browser persistent storage. API endpoints must be exact HTTP
literal-loopback `/api/v1` URLs with explicit ports; origins must be the exact issued own-app origins,
without paths. Redirects and environment HTTP proxies are disabled.

Example target values below are placeholders. Replace all four with exact operator-approved targets:

```sh
python3 tools/mail-prototype/two_node_demo.py \
  --alice-api http://127.0.0.1:8888/api/v1 \
  --bob-api http://127.0.0.1:8889/api/v1 \
  --alice-origin http://127.0.0.1:9000 \
  --bob-origin http://127.0.0.1:9001 \
  --execute --disposable-targets --independent-vaults-signed-installs
```

The script uses only fixed public synthetic subject/body text. It directly hands public cards and
private CHK references between these exact explicitly authorized targets in memory, simulating the
operator's manual out-of-band exchange. It approves the cards it just exported from the two selected
endpoints. This does not authenticate any real-world person. It performs explicit send, waits for a
successful ciphertext CHK, imports and reads at the other endpoint, checks wrong-recipient denial,
checks duplicate admission and sends an explicit reply. Network ciphertext remains published after
local deletion; errors or timeout may leave an uncertain insertion outcome. The script never retries
by manufacturing a new sealed send operation.

For the recipient restart observation, also pass `--restart-recipient` and provide the Bob node's
form password through `CRYPTAD_MAIL_DEMO_BOB_FORM_PASSWORD`. This separately authorizes the exact
host operations `POST /api/v1/apps/mail-prototype/stop` and `POST .../start`. These calls use the host
form-password path, without forwarding browser credentials. The retained browser session is bound
to the installed bundle/origin, so ordinary process stop/start does not itself renew it. Expired or
invalid sessions fail; the script does not bypass bootstrap or create a process token. If restart
is not selected, its summary reports `restart: skipped`, overall is `incomplete`, and exit status
is 2. No complete demonstration is claimed. Restart failure gives a bounded failed result and does
not attempt destructive cleanup.

The only public output is a bounded fixed-key status summary. No token, card, subject/body, message
identifier, hash, CHK, target endpoint or raw exception is printed. The summary distinguishes
operator-attested independent signed installations from observed operations. It cannot establish
independent security review, production eligibility, anonymity or forward secrecy. No raw private
logs or stores are uploaded. Successful delivery to the test app is not a protocol read receipt.

Offline driver tests (no HTTP listener, socket or live operation):

```sh
python3 -m unittest discover -s tools/mail-prototype -p 'test_*.py'
```

These validate opt-in/target handling and fixture command parsing only. They are not evidence of
Java cryptography, process integration or real two-node delivery.
