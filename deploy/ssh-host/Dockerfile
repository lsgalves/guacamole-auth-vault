FROM ubuntu:22.04

ARG VSH_VERSION=0.2.1
ARG SSH_USER=guacuser

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-server \
        ca-certificates \
        wget \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# Create the SSH user. It has no local password — authentication happens via
# Vault one-time passwords validated through PAM.
RUN useradd --create-home --shell /bin/bash "${SSH_USER}" \
    && passwd -d "${SSH_USER}"

# Install vault-ssh-helper.
RUN wget -q \
        "https://releases.hashicorp.com/vault-ssh-helper/${VSH_VERSION}/vault-ssh-helper_${VSH_VERSION}_linux_amd64.zip" \
        -O /tmp/vault-ssh-helper.zip \
    && unzip -q /tmp/vault-ssh-helper.zip -d /usr/local/bin \
    && chmod 0755 /usr/local/bin/vault-ssh-helper \
    && rm /tmp/vault-ssh-helper.zip

COPY vault-ssh-helper.hcl /etc/vault-ssh-helper.d/config.hcl
COPY sshd_config          /etc/ssh/sshd_config
COPY pam_sshd             /etc/pam.d/sshd

# Runtime directories, host keys and the helper log file.
RUN mkdir -p /run/sshd /etc/vault-ssh-helper.d \
    && ssh-keygen -A \
    && touch /var/log/vault-ssh-helper.log

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
