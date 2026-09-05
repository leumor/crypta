---
name: cryptad-runtime-debugging
description: Diagnose live Cryptad JVM hangs, deadlocks, stalled requests, and thread contention with jcmd/jdb.
---

# Cryptad Runtime Debugging

## Overview

- Capture runtime evidence before editing code or restarting the node.
- Prefer `jcmd` for first-response diagnosis because it is lower risk and still works when another debugger is already attached.
- Use `jdb` only when thread dumps and logs are insufficient and interactive inspection or breakpoints are necessary.
- Pair this skill with [$cryptad-architecture](../cryptad-architecture/SKILL.md) when stacks need package context and [$cryptad-build-test](../cryptad-build-test/SKILL.md) after making a fix.

## Guardrails

- Do not restart or kill the running Cryptad process unless the user explicitly asks.
- Do not attach `jdb` if port `5005` already has an established debugger connection unless the user explicitly wants to replace that debugger.
- Capture `VM.command_line` and at least one full `Thread.print -l` dump before changing code.
- Treat `Found one Java-level deadlock` in `jcmd` output as primary evidence; map the waiting thread, owning thread, and monitor objects back to source before proposing a fix.
- Use the smallest safe code change and add a regression test when the failure can be expressed in a unit or concurrency-focused test.

## Workflow

### 1. Identify the JVM exposing JDWP

On Windows PowerShell, start with:

```powershell
Get-NetTCPConnection -LocalPort 5005 -ErrorAction SilentlyContinue |
  Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess
Get-Process -Id <pid> | Select-Object Name,Id,Path,StartTime
jcmd <pid> VM.command_line
```

On macOS shell, start with:

```bash
lsof -nP -iTCP:5005
ps -p <pid> -o pid,ppid,user,lstart,command
jcmd <pid> VM.command_line
```

On Linux shell, start with:

```bash
ss -ltnp '( sport = :5005 )'
ss -tnp '( sport = :5005 or dport = :5005 )'
ps -fp <pid>
jcmd <pid> VM.command_line
```

Interpret the results:

- If nothing is listening on `5005`, the current process is not exposing JDWP on the default port.
- If the connection state is `Established` on Windows, or `lsof` / `ss` shows an established peer on macOS or Linux, another debugger is already attached.
- Confirm the JVM was started with JDWP options similar to `-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=127.0.0.1:5005`.
- `127.0.0.1:5005` means the listener is local-only; remote attach from another host will fail unless the JVM was started with a different bind address.

### 2. Triage with `jcmd` first

Use `jcmd` against the process ID instead of the JDWP socket. The commands are the same on Windows, macOS, and Linux:

```powershell
jcmd <pid> VM.command_line
jcmd <pid> Thread.print -l
```

Capture a class histogram only for a memory investigation; it can pause a live JVM.
Keep raw command lines and dumps local and redact secrets before sharing.

Read `Thread.print -l` in this order:

1. Search for `Found one Java-level deadlock`.
2. Identify the two threads and the monitors each one owns or waits on.
3. Copy the Java stack frames for both threads.
4. Find other threads blocked on the same monitor; those often explain user-visible symptoms such as a frozen web UI or stalled announcements.

Typical Cryptad packages to inspect after a dump:

- `network.crypta.node` for peer management, packet sending, announcers, and schedulers
- `network.crypta.runtime.updater` for updater state, CoreUpdater, and NodeUpdateManager
- `network.crypta.clients.http.updater` for `/core-update/` handlers and browser-facing updater
  actions
- `network.crypta.runtime.endpoints` and `network.crypta.runtime.admin` for FCP/HTTP/TMCI
  bootstrap glue and page-oriented runtime adapters
- `network.crypta.runtime.alerts` for alert lifecycles and operator-facing state propagation
- `network.crypta.clients.http` for stuck HTTP handlers and rendered pages
- `network.crypta.client.async` for fetcher and callback interactions
- `network.crypta.support` for pooled threads, timers, and executor behavior

### 3. Use `jdb` for interactive inspection when needed

Attach to the default local listener only after checking whether another debugger is already connected:

```text
jdb -attach 127.0.0.1:5005
```

Useful `jdb` commands:

```text
threads
thread <thread-id-or-name>
where
where all
locals
print <expression>
stop in network.crypta.runtime.updater.NodeUpdateManager.hasNewCorePackage
clear network.crypta.runtime.updater.NodeUpdateManager.hasNewCorePackage
cont
exit
```

Use `jdb` carefully:

- Set breakpoints on narrow methods, not hot loops or broad package entry points.
- Prefer inspecting blocked threads with `where` and `locals` over stepping through packet-processing code.
- Remember that breakpoints can perturb timing and may hide or reshape races.
- On macOS and Linux, run `jdb` from the same JDK major version as the target JVM when possible.

### 4. Correlate runtime evidence with source

- Open the exact methods from the thread dump before reading surrounding code.
- Look for lock-order inversions such as `A -> B` on one path and `B -> A` on another.
- Pay attention to synchronized manager methods that call synchronized updater methods, callback paths that re-enter shared state, and code that mixes monitor locks with executor callbacks.
- If the failure is not a deadlock but a stalled request flow, consider enabling UID trace logging for the next restart:

```text
logger.priorityDetail=network.crypta.uidtrace:INFO
```

That writes `crypta-uidtrace-latest.log` under the configured log directory and helps trace long-lived request and insert UIDs.

### 5. Turn the diagnosis into a fix

- Keep the change minimal: shorten a lock scope, snapshot state before cross-object calls, or move callbacks outside synchronized sections when safe.
- Add or update a focused regression test near the affected updater, node, or support class.
- Run targeted Gradle verification first:

```powershell
.\gradlew.bat test --tests '*TargetTestClass'
```

```bash
./gradlew test --tests '*TargetTestClass'
```

- If there is no focused test, at least compile and then run the smallest relevant test slice before broader validation.

## Common Patterns

### Deadlock

- `jcmd` reports `Found one Java-level deadlock`.
- One thread usually holds a manager-level monitor while calling into another synchronized component.
- Another thread holds the second component and calls back into the manager.
- Fix by breaking the lock-order inversion, usually by snapshotting state under one lock and calling outward after releasing it.

### Hang without explicit deadlock

- Many worker threads are `BLOCKED` on the same monitor, but `jcmd` reports no Java-level deadlock.
- Find the owning thread and inspect why it is slow, parked, or waiting on I/O.
- Check whether the blocked monitor sits on a frequently rendered HTTP path or peer-announcement path.

### Existing debugger attached

- Windows: `Get-NetTCPConnection` shows port `5005` with an `Established` connection.
- macOS: `lsof -nP -iTCP:5005` shows both the listening JVM socket and an established peer.
- Linux: `ss -tnp '( sport = :5005 or dport = :5005 )'` shows the established peer.
- Use `jcmd` against the PID instead of attaching `jdb`.
- Only replace the existing debugger when the user explicitly asks.
