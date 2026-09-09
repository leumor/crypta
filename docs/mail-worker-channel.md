# Experimental Mail worker channel

Mail runs as a signed AppHost Java child. The daemon brokers a closed list of own-app UI commands
through process-authenticated Platform API polling and replies. Mailbox state, contact approval,
transport scheduling and encrypted app-data persistence belong exclusively to the child.

AppHost supplies `CRYPTAD_MAIL_JAVA`, the absolute Java executable from its own Java 25+ runtime.
The worker launcher requires this value instead of searching the sanitized process `PATH`.
Restricted launches expose the host-selected runtime executables, libraries and fixed public
security configuration read-only, including when the runtime is outside system directories.

The broker holds at most four transient requests, each expiring after thirty seconds. Frames carry
canonical base64 containing at most 384 KiB encoded text. Request identifiers are random; requests
and replies bind the current AppHost launch UUID and installed app version. The bridge supplies the
launch UUID from successful process authentication, never from browser input. Replacement, stop
and crash invalidate old work. There is no daemon mailbox fallback. API admission and capability
checks precede broker calls, and only the own Mail browser origin may submit/read results.

Each worker HTTP exchange has one 25-second deadline covering response headers and the complete
body, with at most 1 MiB accumulated for either success or error responses. Timeout or interruption
cancels the exchange so the single worker scheduler can handle subsequent commands. The browser
SDK starts a separate 30-second overall deadline before submission and carries its abort signal
through bootstrap/session refresh, command/result requests, body reads and polling delays. The UI
uses that bounded SDK path and releases its busy state on failure. A timeout does not undo a daemon
operation or prove that insertion failed; check private operation status before explicitly retrying.

The worker validates complete UTF-8 command payloads as objects containing string values.
Malformed JSON, null or nested command values, and invalid UTF-8 receive a bounded `invalid`
reply without executing a mailbox operation or stopping the worker. Parser diagnostics and
rejected payloads are not written to process logs.

Polling never blocks and broker synchronization never encompasses blocking worker calls. The
host selects the local Platform API endpoint. Callers cannot choose a forwarding address, path,
command or class. Process stdout/stderr remain ordinary logs and carry no private frames. The
browser receives neither process tokens nor launch credentials. Plaintext IPC can exist transiently
inside trusted daemon/worker memory; compromised endpoints remain outside confidentiality claims.
