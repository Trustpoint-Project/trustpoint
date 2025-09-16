FROM debian:bullseye-slim

# Install SoftHSM and dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    softhsm2 \
    libsofthsm2-dev \
    pkcs11-proxy \
    && rm -rf /var/lib/apt/lists/*

# Create the directory for SoftHSM tokens
RUN mkdir -p /var/lib/softhsm/tokens && \
    chmod 700 /var/lib/softhsm/tokens

# Copy the SoftHSM configuration file
COPY softhsm.conf /etc/softhsm/softhsm.conf

# Set environment variable for SoftHSM
ENV SOFTHSM2_CONF=/etc/softhsm/softhsm.conf

# Expose the PKCS#11 Proxy port
EXPOSE 5657

# Start PKCS#11 Proxy without TLS
CMD ["pkcs11-daemon", "--foreground", "--module", "/usr/lib/softhsm/libsofthsm2.so"]