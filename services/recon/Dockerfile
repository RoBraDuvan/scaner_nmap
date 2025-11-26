# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

WORKDIR /app

# Copy source code
COPY . .

# Download dependencies and build
RUN go mod download && go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main ./cmd/server

# Final stage
FROM alpine:latest

# Install runtime dependencies and recon tools
RUN apk --no-cache add ca-certificates bind-tools curl wget unzip libc6-compat gcompat && \
    # Install Subfinder
    wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip -O /tmp/subfinder.zip && \
    unzip -q /tmp/subfinder.zip -d /tmp && \
    mv /tmp/subfinder /usr/local/bin/ && \
    chmod +x /usr/local/bin/subfinder && \
    # Install Httpx
    wget -q https://github.com/projectdiscovery/httpx/releases/download/v1.3.7/httpx_1.3.7_linux_amd64.zip -O /tmp/httpx.zip && \
    unzip -q /tmp/httpx.zip -d /tmp && \
    mv /tmp/httpx /usr/local/bin/ && \
    chmod +x /usr/local/bin/httpx && \
    # Install Amass
    wget -q https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip -O /tmp/amass.zip && \
    unzip -q /tmp/amass.zip -d /tmp && \
    mv /tmp/amass_Linux_amd64/amass /usr/local/bin/ && \
    chmod +x /usr/local/bin/amass && \
    # Cleanup
    rm -rf /tmp/*

WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/main .

# Expose port
EXPOSE 8003

# Run the application
CMD ["./main"]
