# Build stage
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

# Copy source code
COPY . .

# Download dependencies and build
RUN go mod download && go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main ./cmd/server

# Final stage
FROM alpine:latest

# Install runtime dependencies
# procps is required for testssl.sh (needs real ps, not busybox)
# bind-tools provides dig/nslookup for testssl.sh DNS checks
RUN apk --no-cache add ca-certificates curl unzip bash openssl coreutils git chromium procps bind-tools

# =====================================================
# Install Nuclei
# =====================================================
RUN curl -sSL https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip -o nuclei.zip && \
    unzip -q nuclei.zip -d /tmp && \
    mv /tmp/nuclei /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm -f nuclei.zip

# Create nuclei config directory and download templates
RUN mkdir -p /root/.config/nuclei /root/nuclei-templates && \
    nuclei -update-templates 2>&1 || true

# =====================================================
# Install ffuf (Web Fuzzer)
# =====================================================
RUN curl -sSL https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz -o ffuf.tar.gz && \
    tar -xzf ffuf.tar.gz -C /tmp && \
    mv /tmp/ffuf /usr/local/bin/ && \
    chmod +x /usr/local/bin/ffuf && \
    rm -f ffuf.tar.gz

# Download common wordlists for ffuf
RUN mkdir -p /root/wordlists && \
    curl -sSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -o /root/wordlists/common.txt && \
    curl -sSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-small.txt -o /root/wordlists/directory-list-small.txt && \
    curl -sSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt -o /root/wordlists/raft-medium-directories.txt && \
    curl -sSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-files.txt -o /root/wordlists/raft-medium-files.txt

# =====================================================
# Install Gowitness (Screenshot tool)
# =====================================================
RUN curl -sSL https://github.com/sensepost/gowitness/releases/download/3.0.5/gowitness-3.0.5-linux-amd64 -o /usr/local/bin/gowitness && \
    chmod +x /usr/local/bin/gowitness

# Create screenshots directory
RUN mkdir -p /root/screenshots

# =====================================================
# Install testssl.sh (SSL/TLS scanner)
# =====================================================
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh && \
    ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh && \
    chmod +x /opt/testssl.sh/testssl.sh

WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/main .

# Expose port
EXPOSE 8002

# Environment variables for tools
ENV NUCLEI_PATH=/usr/local/bin/nuclei
ENV FFUF_PATH=/usr/local/bin/ffuf
ENV GOWITNESS_PATH=/usr/local/bin/gowitness
ENV TESTSSL_PATH=/usr/local/bin/testssl.sh
ENV WORDLISTS_PATH=/root/wordlists
ENV SCREENSHOTS_PATH=/root/screenshots
ENV CHROME_PATH=/usr/bin/chromium-browser

# Run the application
CMD ["./main"]
