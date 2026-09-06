# syntax=docker/dockerfile:1
FROM node:24.20.0-trixie-slim AS node_lts

FROM docker.io/benyamin/codex-sandbox:latest

COPY --from=node_lts /usr/local/bin/node /usr/local/bin/node
COPY --from=node_lts /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm

ARG CODEX_SSH_AUTHORIZED_KEYS=""

COPY --from=latest_versions /latest/versions.env /usr/local/share/codex-docker-versions.env

ENV DEBIAN_FRONTEND=noninteractive \
    NPM_CONFIG_PREFIX=/usr/local \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    VISUAL=nvim \
    PLAYWRIGHT_REMOTE_WS_ENDPOINT=ws://playwright:3000/ \
    PW_TEST_CONNECT_WS_ENDPOINT=ws://playwright:3000/ \
    UV_INSTALL_DIR=/usr/local/bin \
    UV_NO_MODIFY_PATH=1

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN set -eux; \
    ln -sf ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm; \
    ln -sf ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx; \
    set -a; \
    . /usr/local/share/codex-docker-versions.env; \
    set +a; \
    case "$(dpkg --print-architecture)" in \
      arm64) GITHUB_MCP_ARCH=arm64; ACTIONLINT_ARCH=arm64 ;; \
      amd64) GITHUB_MCP_ARCH=x86_64; ACTIONLINT_ARCH=amd64 ;; \
      *) echo "Unsupported architecture: $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac; \
    mkdir -p -m 755 /etc/apt/keyrings /etc/apt/sources.list.d; \
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
      -o /etc/apt/keyrings/githubcli-archive-keyring.gpg; \
    chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg; \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
      > /etc/apt/sources.list.d/github-cli.list; \
    apt-get update; \
    apt-get upgrade -y; \
    apt-get install -y --no-install-recommends \
      bison \
      bubblewrap \
      build-essential \
      ca-certificates \
      file \
      fd-find \
      fakeroot \
      gh \
      gpgv \
      libevent-dev \
      libfontconfig1 \
      libfreetype6 \
      libharfbuzz0b \
      libprotobuf-dev \
      libssl-dev \
      libutempter-dev \
      neovim \
      openjdk-25-jdk-headless \
      openssh-client \
      openssh-server \
      perl \
      pkg-config \
      protobuf-compiler \
      wget \
      yq \
      zlib1g-dev; \
    apt-get purge -y tmux libncurses-dev libncursesw5-dev || true; \
    apt-get autoremove -y; \
    ln -sf /usr/bin/fdfind /usr/local/bin/fd; \
    npm install --global "@ast-grep/cli@${AST_GREP_VERSION}" "@openai/codex@${CODEX_VERSION}"; \
    test "$(node --version)" = "v24.20.0"; \
    test "$(codex --version)" = "codex-cli ${CODEX_VERSION}"; \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm install --global \
      "playwright@${PLAYWRIGHT_VERSION}" \
      "@playwright/test@${PLAYWRIGHT_VERSION}"; \
    cd /tmp; \
    GITHUB_MCP_ARCHIVE="github-mcp-server_Linux_${GITHUB_MCP_ARCH}.tar.gz"; \
    curl -fsSL -o "${GITHUB_MCP_ARCHIVE}" \
      "https://github.com/github/github-mcp-server/releases/download/${GITHUB_MCP_VERSION}/${GITHUB_MCP_ARCHIVE}"; \
    curl -fsSL -o github-mcp-server_checksums.txt \
      "https://github.com/github/github-mcp-server/releases/download/${GITHUB_MCP_VERSION}/github-mcp-server_${GITHUB_MCP_VERSION#v}_checksums.txt"; \
    grep "  ${GITHUB_MCP_ARCHIVE}$" github-mcp-server_checksums.txt | sha256sum -c -; \
    tar xzf "${GITHUB_MCP_ARCHIVE}"; \
    install -m 0755 github-mcp-server /usr/local/bin/github-mcp-server; \
    rm -f "${GITHUB_MCP_ARCHIVE}" github-mcp-server_checksums.txt github-mcp-server; \
    ACTIONLINT_ARCHIVE="actionlint_${ACTIONLINT_VERSION}_linux_${ACTIONLINT_ARCH}.tar.gz"; \
    curl -fsSL -o "${ACTIONLINT_ARCHIVE}" \
      "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/${ACTIONLINT_ARCHIVE}"; \
    curl -fsSL -o actionlint_checksums.txt \
      "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_checksums.txt"; \
    grep "  ${ACTIONLINT_ARCHIVE}$" actionlint_checksums.txt | sha256sum -c -; \
    tar xzf "${ACTIONLINT_ARCHIVE}" actionlint; \
    install -m 0755 actionlint /usr/local/bin/actionlint; \
    rm -f "${ACTIONLINT_ARCHIVE}" actionlint_checksums.txt actionlint; \
    curl -fsSL -o gnu-keyring.gpg https://ftp.gnu.org/gnu/gnu-keyring.gpg; \
    curl -fsSL -o ncurses.tar.gz "${NCURSES_TARBALL_URL}"; \
    curl -fsSL -o ncurses.tar.gz.sig "${NCURSES_SIG_URL}"; \
    gpgv --keyring ./gnu-keyring.gpg ncurses.tar.gz.sig ncurses.tar.gz; \
    tar xzf ncurses.tar.gz; \
    cd "ncurses-${NCURSES_VERSION}"; \
    export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig; \
    export CPPFLAGS=-I/usr/local/include; \
    export LDFLAGS="-L/usr/local/lib -Wl,-rpath,/usr/local/lib"; \
    export LD_RUN_PATH=/usr/local/lib; \
    ./configure \
      --prefix=/usr/local \
      --with-shared \
      --with-termlib=tinfo \
      --enable-widec \
      --enable-rpath \
      --enable-pc-files \
      --with-pkg-config-libdir=/usr/local/lib/pkgconfig \
      --without-ada \
      --without-cxx-binding \
      --without-debug \
      --without-manpages \
      --without-tests; \
    make -j"$(nproc)"; \
    make install; \
    LD_LIBRARY_PATH=/usr/local/lib tic -x -o /usr/local/share/terminfo misc/terminfo.src; \
    LD_LIBRARY_PATH=/usr/local/lib infocmp -x -A /usr/local/share/terminfo ghostty \
      | awk 'BEGIN { done = 0 } !done && /^ghostty[|,]/ { sub(/^ghostty[|,]/, "xterm-ghostty|"); done = 1 } { print }' \
      | LD_LIBRARY_PATH=/usr/local/lib tic -x -o /usr/local/share/terminfo -; \
    mkdir -p /usr/share/terminfo/g /usr/share/terminfo/x; \
    cp /usr/local/share/terminfo/g/ghostty /usr/share/terminfo/g/ghostty; \
    cp /usr/local/share/terminfo/x/xterm-ghostty /usr/share/terminfo/x/xterm-ghostty; \
    LD_LIBRARY_PATH=/usr/local/lib infocmp -A /usr/share/terminfo ghostty >/dev/null; \
    LD_LIBRARY_PATH=/usr/local/lib infocmp -A /usr/share/terminfo xterm-ghostty >/dev/null; \
    cd /tmp; \
    rm -rf "ncurses-${NCURSES_VERSION}" ncurses.tar.gz ncurses.tar.gz.sig gnu-keyring.gpg; \
    for ncurses_tool in captoinfo clear infocmp infotocap reset tabs tic toe tput tset; do \
      if [ -x "/usr/local/bin/${ncurses_tool}" ] && [ ! -e "/usr/local/bin/${ncurses_tool}.real" ]; then \
        mv "/usr/local/bin/${ncurses_tool}" "/usr/local/bin/${ncurses_tool}.real"; \
        printf '%s\n' \
          '#!/bin/sh' \
          'export LD_LIBRARY_PATH="/usr/local/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"' \
          "exec \"/usr/local/bin/${ncurses_tool}.real\" \"\$@\"" \
          > "/usr/local/bin/${ncurses_tool}"; \
        chmod 0755 "/usr/local/bin/${ncurses_tool}"; \
      fi; \
    done; \
    tic -V | grep -E "^ncurses ${NCURSES_VERSION}([ .]|$)"; \
    pkg-config --modversion ncursesw | grep -E "^${NCURSES_VERSION}([.-]|$)"; \
    export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig; \
    export CPPFLAGS="-I/usr/local/include/ncursesw -I/usr/local/include"; \
    export LDFLAGS="-L/usr/local/lib -Wl,-rpath,/usr/local/lib"; \
    export LD_RUN_PATH=/usr/local/lib; \
    curl -fsSL -o tmux.tar.gz "${TMUX_TARBALL_URL}"; \
    tar xzf tmux.tar.gz; \
    cd "tmux-${TMUX_VERSION}"; \
    ./configure --prefix=/usr/local; \
    make -j"$(nproc)"; \
    make install; \
    test "$(command -v tmux)" = /usr/local/bin/tmux; \
    test "$(tmux -V)" = "tmux ${TMUX_VERSION}"; \
    cd /tmp; \
    rm -rf "tmux-${TMUX_VERSION}" tmux.tar.gz; \
    curl -fsSL -o mosh.tar.gz "${MOSH_TARBALL_URL}"; \
    tar xzf mosh.tar.gz; \
    cd "mosh-${MOSH_VERSION}"; \
    ./configure --prefix=/usr/local; \
    make -j"$(nproc)"; \
    make install; \
    test "$(mosh --version | sed -n 's/^mosh \([^ ]*\).*/\1/p' | head -n 1)" = "${MOSH_VERSION}"; \
    strings /usr/local/bin/mosh-server | grep -F "mosh-server (mosh ${MOSH_VERSION})"; \
    cd /tmp; \
    rm -rf "mosh-${MOSH_VERSION}" mosh.tar.gz; \
    curl -LsSf "https://astral.sh/uv/${UV_VERSION}/install.sh" | sh; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN set -eux; \
    if [ -f /usr/local/bin/zai-codex-entrypoint ]; then \
      sed -i \
        -e 's/^ClientAliveInterval 60$/ClientAliveInterval 0/' \
        -e 's/^ClientAliveCountMax 3$/ClientAliveCountMax 0/' \
        /usr/local/bin/zai-codex-entrypoint; \
    fi; \
    mkdir -p /etc/ssh/authorized_keys /etc/ssh/sshd_config.d /run/sshd; \
    printf '%s\n' \
      'PermitRootLogin yes' \
      'PasswordAuthentication yes' \
      'KbdInteractiveAuthentication yes' \
      'PubkeyAuthentication yes' \
      'AuthorizedKeysFile /etc/ssh/authorized_keys/%u .ssh/authorized_keys' \
      'ClientAliveInterval 0' \
      'ClientAliveCountMax 0' \
      > /etc/ssh/sshd_config.d/99-codex.conf; \
    printf 'root:root\n' | chpasswd; \
    printf '%s\n' \
      'if [ -d /work/cryptad ]; then' \
      '  case "$-" in' \
      '    *i*) cd /work/cryptad || true ;;' \
      '  esac' \
      'fi' \
      > /etc/profile.d/99-cryptad-workdir.sh; \
    if [ -n "${CODEX_SSH_AUTHORIZED_KEYS}" ]; then \
      printf '%s\n' "${CODEX_SSH_AUTHORIZED_KEYS}" > /etc/ssh/authorized_keys/root; \
    else \
      touch /etc/ssh/authorized_keys/root; \
    fi; \
    chmod 0755 /etc/ssh/authorized_keys /run/sshd; \
    chmod 0644 /etc/ssh/authorized_keys/root; \
    ssh-keygen -A; \
    sshd -t

ENV NODE_PATH=/usr/local/lib/node_modules

WORKDIR /work

COPY tmux.conf /etc/tmux.conf
COPY playwright-remote /usr/local/bin/playwright-remote
COPY start-codex-remote-control-daemon.sh /usr/local/bin/start-codex-remote-control-daemon
RUN chmod 0755 \
    /usr/local/bin/playwright-remote \
    /usr/local/bin/start-codex-remote-control-daemon

EXPOSE 22 60000-61000/udp

CMD ["start-codex-remote-control-daemon"]
