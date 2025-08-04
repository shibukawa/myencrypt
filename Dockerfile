# syntax=docker/dockerfile:1

################################################################################
# Build stage
################################################################################
ARG GO_VERSION=1.24.5
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION} AS build
WORKDIR /src

# Download dependencies as a separate step to take advantage of Docker's caching.
# Leverage a cache mount to /go/pkg/mod/ to speed up subsequent builds.
# Leverage bind mounts to go.sum and go.mod to avoid having to copy them into
# the container.
RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=bind,source=go.sum,target=go.sum \
    --mount=type=bind,source=go.mod,target=go.mod \
    go mod download -x

# Build arguments for cross-compilation and version info
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

# Build the application.
# Leverage a cache mount to /go/pkg/mod/ to speed up subsequent builds.
# Leverage a bind mount to the current directory to avoid having to copy the
# source code into the container.
RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=bind,target=. \
    set -e && \
    case "${TARGETOS}-${TARGETARCH}" in \
        linux-arm64) \
            echo "Setting up ARM64 cross-compilation..." && \
            apt-get update -qq && \
            apt-get install -y -qq gcc-aarch64-linux-gnu libc6-dev-arm64-cross && \
            export CC=aarch64-linux-gnu-gcc && \
            export CGO_ENABLED=1 ;; \
        linux-amd64) \
            echo "Setting up AMD64 compilation..." && \
            export CC=gcc && \
            export CGO_ENABLED=1 ;; \
        *) \
            echo "Unsupported platform: ${TARGETOS}-${TARGETARCH}" && \
            exit 1 ;; \
    esac && \
    echo "Building for ${TARGETOS}/${TARGETARCH} with CC=${CC}" && \
    GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /bin/myencrypt ./cmd/myencrypt && \
    echo "Build completed successfully"

################################################################################
# Runtime stage using distroless (CGO-enabled)
################################################################################
FROM gcr.io/distroless/base-debian12:latest AS final

# Copy CA certificates and timezone data from build stage
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the executable from the build stage
COPY --from=build /bin/myencrypt /myencrypt

# Set default environment variables for MyEncrypt
ENV MYENCRYPT_HTTP_PORT=80 \
    MYENCRYPT_BIND_ADDRESS=0.0.0.0 \
    MYENCRYPT_CERT_TTL=24h \
    MYENCRYPT_CA_TTL=19200h \
    MYENCRYPT_ALLOWED_DOMAINS="localhost,*.localhost,*.test,*.example,*.invalid" \
    MYENCRYPT_CERT_STORE_PATH=/data \
    MYENCRYPT_DATABASE_PATH=/data/myencrypt.db

# Expose the internal port (80) - external port is configured via MYENCRYPT_EXPOSE_PORT
EXPOSE 80

# Volume for persistent data
VOLUME ["/data"]

# Run MyEncrypt (container mode will be auto-detected)
# Note: distroless runs as non-root user (65532) by default
ENTRYPOINT ["/myencrypt"]
CMD ["run"]
