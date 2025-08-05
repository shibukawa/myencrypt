# syntax=docker/dockerfile:1

ARG GO_VERSION=1.24.5
ARG TARGETARCH

# Install simple-http-app command
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION} AS build-simple-http-app

WORKDIR /src

RUN --mount=type=bind,src=main.go,target=main.go \
    --mount=type=bind,src=go.mod,target=go.mod \
    CGO_ENABLED=0 GOARCH=$TARGETARCH go build -ldflags="-s -w" -trimpath -o /bin/server

# Deploy image
FROM gcr.io/distroless/static-debian12 AS final

COPY --from=build-simple-http-app /bin/server /bin/server

EXPOSE 80

ENTRYPOINT [ "/bin/server" ]