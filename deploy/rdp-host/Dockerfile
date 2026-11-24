FROM ubuntu:22.04

ARG RDP_USER=rdpuser
# Must match the password stored in Vault KV at secret/guacamole/rdp/rdp-host
ARG RDP_PASSWORD=RdpExampleP@ssw0rd

ENV DEBIAN_FRONTEND=noninteractive

# xrdp + a lightweight XFCE desktop session.
RUN apt-get update \
    && apt-get install -y \
        xrdp \
        xorgxrdp \
        xfce4 \
        xfce4-terminal \
        dbus-x11 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create the RDP user with a password identical to the Vault KV secret. xrdp
# authenticates against local Linux users via PAM.
RUN useradd --create-home --shell /bin/bash "${RDP_USER}" \
    && echo "${RDP_USER}:${RDP_PASSWORD}" | chpasswd \
    && echo "startxfce4" > "/home/${RDP_USER}/.xsession" \
    && chown "${RDP_USER}:${RDP_USER}" "/home/${RDP_USER}/.xsession"

COPY startwm.sh /etc/xrdp/startwm.sh
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /etc/xrdp/startwm.sh /usr/local/bin/entrypoint.sh \
    && mkdir -p /var/run/xrdp /run/dbus

EXPOSE 3389

CMD ["/usr/local/bin/entrypoint.sh"]
