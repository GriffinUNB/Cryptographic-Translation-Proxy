FROM ubuntu:22.04

RUN dpkg --add-architecture i386 && \
    apt-get update && apt-get install -y --no-install-recommends \
    libc6:i386 \
    libgcc-s1:i386 \
    libstdc++6:i386 \
    && rm -rf /var/lib/apt/lists/*

COPY hsm/sim/bl_sim5 /opt/utimaco/sim/bin/
COPY hsm/sim/cs_sim.ini /opt/utimaco/sim/bin/
COPY hsm/sim/devices /opt/utimaco/sim/devices

RUN chmod +x /opt/utimaco/sim/bin/bl_sim5

EXPOSE 3001

COPY hsm/sim/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /opt/utimaco/sim

ENTRYPOINT ["/entrypoint.sh"]