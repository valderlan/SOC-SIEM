FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        hydra \
        iputils-ping \
        netcat-openbsd \
        nmap \
        openssh-client \
        sshpass \
    && rm -rf /var/lib/apt/lists/*

COPY infra/kali-attacker/simulate_attacks.sh /usr/local/bin/simulate_attacks.sh
RUN sed -i 's/\r$//' /usr/local/bin/simulate_attacks.sh \
    && chmod +x /usr/local/bin/simulate_attacks.sh

CMD ["sleep", "infinity"]
