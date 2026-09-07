# Experimental Mail worker channel

Mail runs as a signed AppHost Java child. The daemon brokers a closed list of own-app UI commands
through process-authenticated Platform API polling and replies. Mailbox state, contact approval,
transport scheduling and encrypted app-data persistence belong exclusively to the child.

The broker holds at most four transient requests, each expiring after thirty seconds. Frames carry
canonical base64 containing at most 384 KiB encoded text. Request identifiers are random; requests
and replies bind the current AppHost launch UUID and installed app version. The bridge supplies the
launch UUID from successful process authentication, never from browser input. Replacement, stop
and crash invalidate old work. There is no daemon mailbox fallback. API admission and capability
checks precede broker calls, and only the own Mail browser origin may submit/read results.

Polling never blocks and broker synchronization never encompasses blocking worker calls. The
host selects the local Platform API endpoint. Callers cannot choose a forwarding address, path,
command or class. Process stdout/stderr remain ordinary logs and carry no private frames. The
browser receives neither process tokens nor launch credentials. Plaintext IPC can exist transiently
inside trusted daemon/worker memory; compromised endpoints remain outside confidentiality claims.
