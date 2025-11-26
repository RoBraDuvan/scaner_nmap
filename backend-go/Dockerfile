# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies and nmap
RUN apk add --no-cache git nmap

WORKDIR /app

# Copy source code
COPY . .

# Download dependencies and build
RUN go mod download && go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main ./cmd/server

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates nmap curl unzip

# Install Nuclei
RUN curl -sSL https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip -o nuclei.zip && \
    unzip -q nuclei.zip -d /tmp && \
    mv /tmp/nuclei /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm -f nuclei.zip

# Create nuclei config directory and download templates
RUN mkdir -p /root/.config/nuclei /root/nuclei-templates && \
    nuclei -update-templates 2>&1 || true && \
    ls -la /root/nuclei-templates/ | head -5 || echo "Templates directory check"

WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/main .

# Expose port
EXPOSE 8001

# Run the application
CMD ["./main"]
