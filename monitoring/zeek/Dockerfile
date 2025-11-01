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

# Create zeek user matching host UID/GID (1000:1000)
RUN groupadd -g 1000 zeek && \
    useradd -u 1000 -g 1000 -m zeek

# Configure zeekctl
RUN echo "LogDir = /mnt/zeek-logs/logs" >> /usr/local/zeek/etc/zeekctl.cfg && \
    echo "SpoolDir = /mnt/zeek-logs/spool" >> /usr/local/zeek/etc/zeekctl.cfg

# Set ownership of zeek directories
RUN chown -R zeek:zeek /usr/local/zeek /mnt/zeek-logs

# Copy startup script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD /usr/local/zeek/bin/zeekctl status | grep -q "running" || exit 1

WORKDIR /usr/local/zeek

# Switch to zeek user
USER zeek

ENTRYPOINT ["/entrypoint.sh"]
git config --global user.email "ferran.garriga@github.com" && git config --global user.name "garrigueta"