FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-server \
        ca-certificates \
        tini \
        iproute2 \
        procps \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /etc/ssh/sshd_config.d

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY tunnel-monitor.sh /usr/local/bin/tunnel-monitor.sh
COPY sshd_config /etc/ssh/sshd_config

RUN chmod 0755 \
        /usr/local/bin/docker-entrypoint.sh \
        /usr/local/bin/tunnel-monitor.sh

EXPOSE 9000 9001 9002

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
