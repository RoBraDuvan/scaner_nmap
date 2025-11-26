# Build stage
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

COPY . .

RUN go mod download && go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main ./cmd/server

# Final stage
FROM alpine:latest

# Install dependencies and tools
RUN apk --no-cache add ca-certificates curl wget unzip python3 py3-pip git libc6-compat gcompat && \
    # Install Kiterunner
    wget -q https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_amd64.tar.gz -O /tmp/kiterunner.tar.gz && \
    tar -xzf /tmp/kiterunner.tar.gz -C /tmp && \
    mv /tmp/kr /usr/local/bin/ && \
    chmod +x /usr/local/bin/kr && \
    # Install ffuf
    wget -q https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz -O /tmp/ffuf.tar.gz && \
    tar -xzf /tmp/ffuf.tar.gz -C /tmp && \
    mv /tmp/ffuf /usr/local/bin/ && \
    chmod +x /usr/local/bin/ffuf && \
    # Create wordlists directory
    mkdir -p /usr/share/wordlists/kiterunner && \
    # Download Kiterunner wordlists
    wget -q https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite -O /usr/share/wordlists/kiterunner/routes-small.kite || true && \
    wget -q https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite -O /usr/share/wordlists/kiterunner/routes-large.kite || true && \
    # Cleanup
    rm -rf /tmp/*

# Install Arjun via pip
RUN pip3 install --break-system-packages arjun && \
    ln -sf /usr/bin/arjun /usr/local/bin/arjun || true

WORKDIR /root/

COPY --from=builder /app/main .

EXPOSE 8004

CMD ["./main"]
