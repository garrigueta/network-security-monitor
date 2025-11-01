FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV ZEEK_VERSION=6.0.3

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    flex \
    bison \
    libpcap-dev \
    libssl-dev \
    python3 \
    python3-dev \
    swig \
    zlib1g-dev \
    libmaxminddb-dev \
    curl \
    git \
    ethtool \
    iproute2 \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Download and install Zeek
WORKDIR /tmp
RUN curl -L https://download.zeek.org/zeek-${ZEEK_VERSION}.tar.gz | tar xzf - && \
    cd zeek-${ZEEK_VERSION} && \
    ./configure --prefix=/usr/local/zeek && \
    make -j$(nproc) && \
    make install && \
    cd / && \
    rm -rf /tmp/zeek-${ZEEK_VERSION}

# Add Zeek to PATH
ENV PATH="/usr/local/zeek/bin:${PATH}"

# Create necessary directories
RUN mkdir -p /mnt/zeek-logs/logs /mnt/zeek-logs/spool

# Configure zeekctl
RUN echo "LogDir = /mnt/zeek-logs/logs" >> /usr/local/zeek/etc/zeekctl.cfg && \
    echo "SpoolDir = /mnt/zeek-logs/spool" >> /usr/local/zeek/etc/zeekctl.cfg

# Copy startup script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD /usr/local/zeek/bin/zeekctl status | grep -q "running" || exit 1

WORKDIR /usr/local/zeek

ENTRYPOINT ["/entrypoint.sh"]
