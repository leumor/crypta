# Codex Docker stack

Use this stack to run the Cryptad Codex container and a remote Playwright browser server from a
tracked repository configuration.

## Prerequisites

- Docker with Compose v2 and BuildKit support.
- Network access to pull base images and download upstream release assets.
- Optional Tailscale settings in repo-root `.env`. The root `.env` file is ignored and must not be
  committed.

## Configure

From this directory:

```bash
test -f ../../.env || cp .env.example ../../.env
```

Edit `../../.env` for local values only. Tool versions are not configured in `.env`; they are
resolved during Docker build by the `latest-versions` build-only image and written to
`/usr/local/share/codex-docker-versions.env` in both runtime images.

The default local Codex-derived image tag is `codex-crypta:0.153.4`, identifying the reviewed
Codex CLI baseline. The build resolves and installs the latest stable CLI, which may be newer.
Set `CODEX_IMAGE_TAG` in `../../.env` only when you need a different local image tag.

The Codex container permits root SSH login with password `root`. It also supports key-based login:
set `CODEX_SSH_AUTHORIZED_KEYS` to one or more public keys in `../../.env`. Public key values may
contain spaces because Compose reads this file directly; do not source `../../.env` as a shell
script. Do not commit private keys or local tokens, and keep SSH access limited to the
Docker/Tailscale paths you intend to use.
Interactive SSH login shells start in `/work/cryptad`.

## Version resolution

Compose builds a local `latest-versions` image first. That image resolves the stable latest releases
for Codex CLI, ast-grep, uv, GitHub MCP server, actionlint, Mosh, tmux, Playwright, and ncurses,
then emits a shared `versions.env` file. The Codex and Playwright images both copy that file so a
single build uses one consistent version set.

The Codex image builds ncurses, tmux, and Mosh from source. It does not install apt `tmux` or apt
`libncurses-dev`; `libevent-dev` remains an apt build dependency for tmux. The Playwright browser
server is a local image that installs the matching Playwright npm package and browser binaries.

The Compose build configuration uses `no_cache: true` for all four images. This makes builds slower,
but it ensures each build re-resolves latest upstream versions instead of reusing a cached resolver
layer. All builds also pull their base images.
The resolver uses Debian 13 (trixie), and both runtime images use Node.js 24.20.0 LTS.
The Codex image installs the resolved CLI version and checks the command on PATH; its local
image tag is a label, while `versions.env` records the installed tool versions.

## Start the stack

Run from `tools/codex-docker`:

```bash
docker compose --env-file ../../.env up -d --build codex playwright
```

Start Tailscale only when you need the remote shell helper:

```bash
docker compose --env-file ../../.env up -d tailscale-shell
```

The Tailscale shell service receives only the Tailscale-related settings from `../../.env`. It does
not mount or source the whole file, so unrelated values such as `CODEX_SSH_AUTHORIZED_KEYS` cannot
break Tailscale startup.

List services:

```bash
docker compose --env-file ../../.env ps
```

## Mosh

Mosh uses SSH for authentication and then connects to `mosh-server` over UDP, so the client must be
able to reach the Codex container address over UDP ports `60000-61000`. With the default Docker
subnet and Tailscale route, connect to the Codex container directly:

```bash
mosh root@172.30.70.10
```

Default Mosh login shells also start in `/work/cryptad`.

## Playwright endpoints

| Caller | Endpoint |
| --- | --- |
| Codex container | `ws://playwright:3000/` |
| Host | `ws://127.0.0.1:${PLAYWRIGHT_HOST_PORT:-3000}/` |

The Playwright service publishes only to host loopback. Other containers in the Compose network use
the service name `playwright`.

## Use Playwright from Codex

The Codex image installs the matching `playwright` and `@playwright/test` npm packages without
browser binaries. Browser binaries live in the local `codex-crypta-playwright:local` image.

Check the CLI:

```bash
docker compose --env-file ../../.env exec codex playwright --version
```

Run a Playwright test through the remote server:

```bash
docker compose --env-file ../../.env exec codex playwright-remote test <spec>
```

The `playwright-remote` wrapper sets `PW_TEST_CONNECT_WS_ENDPOINT` to `ws://playwright:3000/` when
the variable is not already set.

From the host, use the version recorded in the Playwright container:

```bash
PLAYWRIGHT_VERSION="$(
  docker compose --env-file ../../.env exec -T playwright \
    sh -lc '. /usr/local/share/codex-docker-versions.env && printf "%s\n" "$PLAYWRIGHT_VERSION"'
)"
PW_TEST_CONNECT_WS_ENDPOINT=ws://127.0.0.1:${PLAYWRIGHT_HOST_PORT:-3000}/ npx -y "playwright@${PLAYWRIGHT_VERSION}" test
```

## Target URL rules

- Use `http://codex:<port>/` for servers running inside the Codex container. Bind those servers to
  `0.0.0.0`, not only `127.0.0.1`.
- Use `http://host.docker.internal:<port>/` for servers running on the host.
- Do not use `localhost` from inside the Playwright browser container unless the target server is
  inside that same container.

## Validation

Static checks:

```bash
docker compose --env-file ../../.env config --quiet
git status --short --ignored . ../../.env
rg -n "tskey-auth-[A-Za-z0-9]{8,}|OPENAI_API_KEY=|GITHUB_TOKEN=|BEGIN OPENSSH|PRIVATE KEY" \
  AGENTS.md .gitignore .agents/skills/cryptad-codex-docker tools/codex-docker tools/README.md \
  --glob '!tools/codex-docker/README.md'
```

Container checks:

```bash
docker compose --env-file ../../.env build latest-versions
docker compose --env-file ../../.env up -d --build codex playwright
docker compose --env-file ../../.env ps codex playwright
docker compose --env-file ../../.env exec codex cat /usr/local/share/codex-docker-versions.env
docker compose --env-file ../../.env exec playwright cat /usr/local/share/codex-docker-versions.env
docker compose --env-file ../../.env exec codex codex --version
docker compose --env-file ../../.env exec codex github-mcp-server --version
docker compose --env-file ../../.env exec codex actionlint -version
docker compose --env-file ../../.env exec codex tic -V
docker compose --env-file ../../.env exec codex pkg-config --modversion ncursesw
docker compose --env-file ../../.env exec codex sh -lc 'command -v tmux && tmux -V'
docker compose --env-file ../../.env exec codex sh -lc 'command -v mosh && command -v mosh-server'
docker compose --env-file ../../.env exec codex mosh --version
docker compose --env-file ../../.env exec codex sh -lc 'strings "$(command -v mosh-server)" | grep -F "mosh-server (mosh" | head -n 1'
docker compose --env-file ../../.env exec -w /root codex bash -lic pwd
docker compose --env-file ../../.env exec codex playwright --version
docker compose --env-file ../../.env exec playwright playwright --version
docker compose --env-file ../../.env exec playwright node --version
```

Use the root project test commands only when a code change also touches Java or Gradle behavior.

## Troubleshooting

- If builds seem slow, check whether `no_cache: true` is doing its job; latest version probing is
  intentionally uncached.
- If a GitHub, npm, or GNU download fails, rerun after confirming upstream availability and local
  network access.
- If Chromium crashes under load, confirm the `playwright` service still uses `ipc: host`.
- If a test cannot reach a local server, check whether the server is on the host, the Codex
  container, or the Playwright container and use the matching target URL rule above.
- If `docker compose` ignores values from `../../.env`, pass `--env-file ../../.env` explicitly.
- If the Codex image tag is not `codex-crypta:0.153.4`, check whether `CODEX_IMAGE_TAG` is set in
  `../../.env`.
- If Mosh authenticates over SSH but cannot attach, confirm that the client accepts the Tailscale
  subnet route and that UDP `60000-61000` can reach the Codex container address.
- If the host port is busy, change `PLAYWRIGHT_HOST_PORT` in `../../.env`.
