FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        iproute2 \
        nftables \
        nginx \
        openssh-server \
        suricata \
    && mkdir -p /usr/share/keyrings /var/run/sshd /var/log/suricata /etc/soclab-protected \
    && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends wazuh-agent=4.14.8-1 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash soclab-user \
    && echo "soclab-user:SocLabTarget2026!" | chpasswd \
    && printf "soclab-protected-seed\n" > /etc/soclab-protected/sensitive.conf

COPY infra/linux-target/index.html /var/www/html/index.html
COPY infra/linux-target/local.rules /etc/suricata/rules/local.rules
COPY infra/linux-target/ossec.conf.tmpl /opt/soclab/ossec.conf.tmpl
COPY infra/linux-target/entrypoint.sh /opt/soclab/entrypoint.sh
RUN sed -i 's/\r$//' /opt/soclab/entrypoint.sh \
    && chmod +x /opt/soclab/entrypoint.sh

EXPOSE 22 80 8080

ENTRYPOINT ["/opt/soclab/entrypoint.sh"]
