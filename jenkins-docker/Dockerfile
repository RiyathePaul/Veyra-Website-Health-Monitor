
FROM jenkins/jenkins:lts-jdk21

USER root

# Install Python, pip, and virtual environment support
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       python3 \
       python3-pip \
       python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Install Docker CLI
COPY --from=docker:cli /usr/local/bin/docker /usr/local/bin/docker

# Install Docker Compose plugin
RUN mkdir -p /usr/local/lib/docker/cli-plugins \
    && curl -fSL "https://github.com/docker/compose/releases/download/v2.39.4/docker-compose-linux-x86_64" \
       -o /usr/local/lib/docker/cli-plugins/docker-compose \
    && chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

USER jenkins
