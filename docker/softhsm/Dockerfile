FROM debian:bullseye-slim

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    softhsm2 \
    libsofthsm2-dev \
    git \
    build-essential \
    cmake \
    ca-certificates \
    libssl-dev \
    libseccomp-dev \
    socat \
    && rm -rf /var/lib/apt/lists/*

# Clone and build pkcs11-proxy
RUN git clone https://github.com/SUNET/pkcs11-proxy.git /tmp/pkcs11-proxy && \
    cd /tmp/pkcs11-proxy && \
    mkdir build && cd build && \
    cmake .. && \
    make && \
    make install && \
    rm -rf /tmp/pkcs11-proxy

# Create the directory for SoftHSM tokens
RUN mkdir -p /var/lib/softhsm/tokens && \
    chmod 700 /var/lib/softhsm/tokens

# Create directory for PKCS#11 proxy socket
RUN mkdir -p /tmp/pkcs11-socket && chmod 755 /tmp/pkcs11-socket

# Copy the SoftHSM configuration file
COPY docker/softhsm/softhsm.conf /etc/softhsm/softhsm.conf

# Set environment variable for SoftHSM
ENV SOFTHSM2_CONF=/etc/softhsm/softhsm.conf

# Expose the PKCS#11 Proxy port
EXPOSE 5657

# Start PKCS#11 Proxy with Unix socket and bridge to TCP port
CMD sh -c 'pkcs11-daemon /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so /tmp/pkcs11-socket & sleep 2 && socat TCP-LISTEN:5657,fork,reuseaddr UNIX-CONNECT:/tmp/pkcs11-socket/socket.pkcs11'