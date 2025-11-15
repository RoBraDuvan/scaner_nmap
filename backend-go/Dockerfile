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

# Install nmap and ca-certificates
RUN apk --no-cache add ca-certificates nmap

WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/main .

# Expose port
EXPOSE 8001

# Run the application
CMD ["./main"]
