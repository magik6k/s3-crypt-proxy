# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install ca-certificates for HTTPS
RUN apk add --no-cache ca-certificates

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /s3-crypt-proxy ./cmd/s3-crypt-proxy

# Runtime stage
FROM scratch

# Copy CA certificates for HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary
COPY --from=builder /s3-crypt-proxy /s3-crypt-proxy

# Expose ports
EXPOSE 8080 8081

# Run
ENTRYPOINT ["/s3-crypt-proxy"]
