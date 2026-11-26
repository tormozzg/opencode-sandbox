FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8

# Defaults are used when no build args are passed (e.g. on macOS, where the
# host IDs do not have to be mirrored inside the container).
ARG USER_ID=1000
ARG GROUP_ID=1000

RUN groupadd -g ${GROUP_ID} opencode && \
			useradd -l -u ${USER_ID} -g opencode -m opencode

#Instapp packages
RUN apt-get update &&  apt-get install --no-install-recommends -y python3 python3-pip python3-venv git curl ca-certificates wget unzip zip shellcheck sudo

# Allow opencode to run sudo without a password (for installing packages at runtime)
RUN echo 'opencode ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/opencode && \
    chmod 0440 /etc/sudoers.d/opencode

# Create a dedicated virtual environment
RUN python3 -m venv /opt/opencode-venv
# Ansible MCP needs ansible-lint for its lint tools
RUN /opt/opencode-venv/bin/pip install --no-cache-dir ansible-lint

# Create activation script for agents
RUN echo '#!/bin/bash\nsource /opt/opencode-venv/bin/activate\nexec "$@"' > /usr/local/bin/activate-venv && \
    chmod +x /usr/local/bin/activate-venv

# Set environment variables to use venv Python
ENV PATH="/opt/opencode-venv/bin:${PATH}"
ENV VIRTUAL_ENV="/opt/opencode-venv"

RUN chown -R opencode:opencode /opt/opencode-venv

ENV SKIP_EGRESS_FIREWALL="true"

RUN rm -rf /var/lib/apt/lists/*

# Optional GUI desktop stack: Xvfb (display :99) + x11vnc (VNC servers) +
# the xfce4 desktop incl. dbus-x11; started by /usr/local/bin/oc-sand-desktop
# only when OC_SAND_DESKTOP=1, so everything here is inert without the
# desktop. procps provides pgrep for the starter's idempotency check.
# iproute2 provides the `ip` binary the starter uses to detect the docker
# bridge gateway IP for the x11vnc -allow source restriction — this image
# is built --no-install-recommends and has no `ip` binary without it, so
# gateway detection would fail closed on every boot. The apt lists were
# removed above, so this layer updates them itself.
RUN apt-get update && apt-get install --no-install-recommends -y xvfb x11vnc dbus-x11 xauth procps iproute2 xfce4 thunar xfce4-terminal

USER opencode

COPY --chmod=755 entrypoint.sh /entrypoint.sh
COPY --chmod=0755 oc-sand-desktop /usr/local/bin/oc-sand-desktop
ENTRYPOINT [ "/entrypoint.sh" ]

SHELL ["/bin/bash", "-c"]

# The single DISPLAY mechanism (GUI plan, resolved decision 9): docker exec
# sessions do not run the entrypoint, so the desktop DISPLAY=:99 has to come
# from the image ENV. It is inert without the desktop: no X server listens
# on :99 unless oc-sand-desktop started one.
ENV DISPLAY=:99

ENV JAVA_HOME="/home/opencode/.sdkman/candidates/java/current"
ENV OPENCODE_PATH="/home/opencode/.opencode/bin"
ENV PATH="$OPENCODE_PATH:$JAVA_HOME/bin:$PATH"

RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.8/install.sh | bash
ENV NVM_DIR=/home/opencode/.nvm
ENV NODE_VERSION="24.15.0"
RUN bash -c "source $NVM_DIR/nvm.sh && nvm install $NODE_VERSION"
ENV PATH="${NVM_DIR}/versions/node/v${NODE_VERSION}/bin:${PATH}"

RUN curl -s "https://get.sdkman.io" | bash

# Install LSP servers
RUN npm install -g yaml-language-server bash-language-server bun
# Pre-install MCP servers so npx config entries resolve locally (no first-run download)
RUN npm install -g @ansible/ansible-mcp-server

RUN npm install -g opencode-ai@1.19.6


WORKDIR /workspace


