# File: Dockerfile.tpl
# Purpose: Multi-stage Go application Dockerfile
# Generated for: {{PROJECT_NAME}}

# Build stage
FROM golang:1.21-alpine as builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=$(git describe --tags --always)" \
    -o /app/server ./cmd/server

# Production stage
FROM scratch as production

WORKDIR /app

# Copy CA certificates for HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy binary
COPY --from=builder /app/server /app/server

# Set environment
ENV TZ=UTC

# Expose port
EXPOSE 8080

# Health check (note: scratch image doesn't have curl/wget)
# Use a sidecar or external health check mechanism

# Start application
ENTRYPOINT ["/app/server"]
