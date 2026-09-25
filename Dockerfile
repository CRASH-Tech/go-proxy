# syntax=docker/dockerfile:1

# --- build stage ---
# Runs on the build machine's own platform and cross-compiles for the target,
# so multi-arch builds do not compile Go under emulation.
FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS build
ARG TARGETOS TARGETARCH TARGETVARIANT
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO disabled -> fully static binary that runs on the alpine runtime image.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags "-s -w" -o /out/goproxy .

# --- runtime stage ---
FROM alpine:3.20
# The node shells out to `ip` (iproute2) for its TUN and pushed routes, and to
# `iptables` for GOPROXY_MASQUERADE.
RUN apk add --no-cache iptables ip6tables iproute2
COPY --from=build /out/goproxy /usr/local/bin/goproxy
ENTRYPOINT ["goproxy"]
# Run a node with the "node" command (set in compose); config comes from env.
CMD ["env"]
