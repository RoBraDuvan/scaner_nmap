# syntax=docker/dockerfile:1.4

# Build stage
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

# Copy go.mod first and download dependencies
COPY go.mod ./
RUN go mod download || true

# Copy rest of source code
COPY . .

# Tidy and build
RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main ./cmd/server

# Final stage
FROM python:3.11-alpine

# Install system dependencies
RUN apk --no-cache add \
    ca-certificates \
    curl \
    wget \
    git \
    bash \
    jq \
    aws-cli \
    libc6-compat \
    gcompat

# =====================================================
# Install Trivy
# =====================================================
RUN wget -q https://github.com/aquasecurity/trivy/releases/download/v0.48.3/trivy_0.48.3_Linux-64bit.tar.gz -O /tmp/trivy.tar.gz && \
    tar -xzf /tmp/trivy.tar.gz -C /tmp && \
    mv /tmp/trivy /usr/local/bin/ && \
    chmod +x /usr/local/bin/trivy && \
    rm -rf /tmp/*

# =====================================================
# Install Prowler
# =====================================================
RUN pip3 install --no-cache-dir prowler && \
    echo '#!/bin/sh' > /usr/local/bin/prowler && \
    echo 'exec python3 -m prowler "$@"' >> /usr/local/bin/prowler && \
    chmod +x /usr/local/bin/prowler

# =====================================================
# Install ScoutSuite
# =====================================================
RUN pip3 install --no-cache-dir scoutsuite && \
    echo '#!/usr/bin/env python3' > /usr/local/bin/scout && \
    echo 'import sys' >> /usr/local/bin/scout && \
    echo 'from ScoutSuite.__main__ import run_from_cli' >> /usr/local/bin/scout && \
    echo 'sys.exit(run_from_cli())' >> /usr/local/bin/scout && \
    chmod +x /usr/local/bin/scout

# Cleanup
RUN rm -rf /var/cache/apk/* /tmp/*

# Create directories for cloud credentials
RUN mkdir -p /root/.aws /root/.azure /root/.config/gcloud /root/credentials

WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/main .

# Environment variables
ENV TRIVY_PATH=/usr/local/bin/trivy
ENV PROWLER_PATH=/usr/local/bin/prowler
ENV SCOUTSUITE_PATH=/usr/local/bin/scout

# Expose port
EXPOSE 8006

CMD ["./main"]
