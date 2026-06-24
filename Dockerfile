# Runtime-only image for micro-auth.
# Build the release binary on the host first: cargo build --release
# Then package: docker build -t micro-auth .

FROM ubuntu:24.04
#FROM debian:bookworm-slim # GLIBC_2.36

# Install runtime dependencies for HTTPS, CA certificates, and healthcheck
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libssl3 && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user for security (Ubuntu 24.04 already has UID 1000 as 'ubuntu')
RUN if id ubuntu &>/dev/null; then \
      groupmod -n appuser ubuntu && \
      usermod -l appuser -d /home/appuser -m -g appuser ubuntu; \
    else \
      useradd -m -u 1000 appuser; \
    fi

WORKDIR /app

COPY target/release/micro-auth /app/micro-auth

COPY config /app/config

RUN mkdir -p /app/data && \
    chown -R appuser:appuser /app

USER appuser

ENV RUST_BACKTRACE=1

EXPOSE 3324

CMD ["/app/micro-auth"]
