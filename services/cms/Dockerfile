# Build stage
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app
COPY . .

RUN go mod download && go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main ./cmd/server

# Final stage
FROM ruby:3.2-alpine

# Install system dependencies
RUN apk --no-cache add \
    ca-certificates \
    curl \
    wget \
    git \
    python3 \
    py3-pip \
    py3-requests \
    libffi-dev \
    build-base \
    ruby-dev \
    libcurl \
    bash \
    libc6-compat \
    gcompat \
    perl \
    perl-dev \
    make

# =====================================================
# Install WhatWeb
# =====================================================
RUN git clone https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb && \
    cd /opt/whatweb && \
    bundle install --without development test && \
    ln -sf /opt/whatweb/whatweb /usr/local/bin/whatweb

# =====================================================
# Install CMSeeK
# =====================================================
RUN git clone https://github.com/Tuhinshubhra/CMSeeK /opt/cmseek && \
    cd /opt/cmseek && \
    pip3 install --break-system-packages -r requirements.txt && \
    chmod +x cmseek.py && \
    ln -sf /opt/cmseek/cmseek.py /usr/local/bin/cmseek

# =====================================================
# Install WPScan
# =====================================================
RUN gem install wpscan --no-document && \
    ln -sf /usr/local/bundle/bin/wpscan /usr/local/bin/wpscan || true

# =====================================================
# Install JoomScan (Joomla Scanner)
# =====================================================
RUN git clone https://github.com/OWASP/joomscan.git /opt/joomscan && \
    cd /opt/joomscan && \
    chmod +x joomscan.pl && \
    ln -sf /opt/joomscan/joomscan.pl /usr/local/bin/joomscan

# =====================================================
# Install Droopescan (Multi-CMS: Drupal, Joomla, Moodle, SilverStripe)
# =====================================================
RUN pip3 install --break-system-packages droopescan && \
    ln -sf /usr/bin/droopescan /usr/local/bin/droopescan || true

# Clean up
RUN rm -rf /var/cache/apk/* /tmp/*

WORKDIR /root/
COPY --from=builder /app/main .

ENV WHATWEB_PATH=/usr/local/bin/whatweb
ENV CMSEEK_PATH=/opt/cmseek/cmseek.py
ENV WPSCAN_PATH=/usr/local/bin/wpscan
ENV JOOMSCAN_PATH=/usr/local/bin/joomscan
ENV DROOPESCAN_PATH=/usr/local/bin/droopescan

EXPOSE 8005

CMD ["./main"]
