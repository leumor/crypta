ARG TAILSCALE_VERSION=latest
FROM tailscale/tailscale:${TAILSCALE_VERSION}

RUN apk upgrade --no-cache && apk add --no-cache bash docker-cli jq

COPY codex cryptad-containers cryptad-shell cryptad-tailscale-entrypoint /usr/local/bin/
RUN chmod +x \
  /usr/local/bin/codex \
  /usr/local/bin/cryptad-containers \
  /usr/local/bin/cryptad-shell \
  /usr/local/bin/cryptad-tailscale-entrypoint

ENTRYPOINT ["/usr/local/bin/cryptad-tailscale-entrypoint"]
