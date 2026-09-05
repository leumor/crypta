---
name: cryptad-codex-docker
description: Maintain Cryptad's tracked Codex Docker stack, Playwright remote browser server, helper scripts, and related docs under tools/codex-docker.
---

# Cryptad Codex Docker

Use this skill before changing `tools/codex-docker`, the Codex Docker helper scripts, the
Playwright remote browser service, or docs that describe this stack.

## Source of truth

- Runbook: `tools/codex-docker/README.md`
- Compose file: `tools/codex-docker/compose.yaml`
- Codex image: `tools/codex-docker/Dockerfile`
- Shared version resolver image: `tools/codex-docker/Dockerfile.versions`
- Playwright browser-server image: `tools/codex-docker/Dockerfile.playwright`
- Tailscale shell helpers: `tools/codex-docker/tailscale-shell/`

## Guardrails

- Never commit `.env`, Tailscale auth keys, SSH keys, GitHub tokens, OpenAI keys, or host-specific
  private paths.
- Keep tool versions resolved by the build-only `latest-versions` image, then copied into both
  runtime images as `/usr/local/share/codex-docker-versions.env`. Do not reintroduce `.env` knobs
  for GitHub MCP, actionlint, Mosh, tmux, ncurses, or Playwright versions.
- Keep the Playwright browser-server image and the Codex image on the same resolved Playwright npm
  version.
- Keep browser binaries in the Playwright container. The Codex image owns only the CLI/test runner
  npm packages and the `playwright-remote` wrapper.
- Keep the internal Playwright endpoint stable at `ws://playwright:3000/` unless the runbook and
  Compose environment are updated together.
- Keep host exposure bound to loopback unless the user explicitly asks for a wider bind address and
  accepts the local security impact.

## Workflow

1. Read `tools/codex-docker/README.md` before editing Compose, Dockerfile, or helper scripts.
2. Inspect the current Compose shape with `docker compose --env-file ../../.env config --quiet` from
   `tools/codex-docker`.
3. Make the smallest change to the Docker stack and update the runbook in the same change.
4. When resolver logic changes, build `latest-versions` first and inspect the emitted
   `versions.env` before rebuilding runtime images.
5. Validate that root `.env` and any local generated outputs remain ignored.
6. Run a Playwright remote-connection smoke test when the Playwright service, image version,
   endpoint, or wrapper changes.

## Validation

Choose checks for the changed layer. Documentation-only changes need command/link review;
Compose edits need config validation; image/helper changes need the affected build and smoke test.
Recreating services with `up` affects running containers: use an isolated stack or existing user
authorization for that restart. The commands below are a menu, not an unconditional sequence.

From `tools/codex-docker`:

```bash
docker compose --env-file ../../.env config --quiet
docker compose --env-file ../../.env build latest-versions
docker compose --env-file ../../.env up -d --build codex playwright
docker compose --env-file ../../.env exec codex cat /usr/local/share/codex-docker-versions.env
docker compose --env-file ../../.env exec playwright cat /usr/local/share/codex-docker-versions.env
docker compose --env-file ../../.env exec codex mosh --version
docker compose --env-file ../../.env exec codex playwright --version
docker compose --env-file ../../.env exec playwright playwright --version
docker compose --env-file ../../.env exec playwright node --version
```

For a browser smoke test, connect from the Codex container to `ws://playwright:3000/` with the
matching Playwright package and open a simple `data:text/html` page.
