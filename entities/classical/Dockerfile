FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/* && \
    mkdir -p /work

COPY hsm/qpki /usr/local/bin/qpki
COPY hsm/profiles /opt/qpki/profiles
COPY hsm/libcs_pkcs11_R3.so /opt/utimaco/p11/libcs_pkcs11_R3.so
COPY hsm/p11tool2 /usr/local/bin/p11tool2
COPY hsm/cxitool /usr/local/bin/cxitool
COPY hsm/csadm /usr/local/bin/csadm
COPY hsm/libcxi.so /opt/utimaco/p11/libcxi.so
COPY hsm/keys /opt/utimaco/keys
RUN chmod +x /usr/local/bin/p11tool2 /usr/local/bin/cxitool /usr/local/bin/csadm

COPY hsm/utimaco-simulator.yaml /etc/qpki/utimaco-simulator.yaml
COPY hsm/cs_pkcs11_R3.cfg /opt/utimaco/p11/cs_pkcs11_R3.cfg

ENV CS_PKCS11_R3_CFG=/opt/utimaco/p11/cs_pkcs11_R3.cfg
ENV QPKI_PROFILES=/opt/qpki/profiles
ENV PATH="/usr/local/bin:${PATH}"

RUN qpki --help > /dev/null 2>&1

COPY entities/classical/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]