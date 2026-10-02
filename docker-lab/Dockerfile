FROM debian:13-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server iproute2 procps sudo ca-certificates && rm -rf /var/lib/apt/lists/*
RUN echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config && echo 'PermitEmptyPasswords yes' >> /etc/ssh/sshd_config
COPY run-lab.sh /run-lab.sh
RUN chmod +x /run-lab.sh
CMD ["/run-lab.sh"]
