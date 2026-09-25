# syntax=docker/dockerfile:1

# --- build stage ---
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO disabled -> fully static binary that runs on the alpine runtime image.
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/goproxy .

# --- runtime stage ---
FROM alpine:3.20
# The tunnel shells out to `ip` (iproute2) and `iptables` for TUN config and NAT.
RUN apk add --no-cache iptables ip6tables iproute2
COPY --from=build /out/goproxy /usr/local/bin/goproxy
ENTRYPOINT ["goproxy"]
# Run a node with the "node" command (set in compose); config comes from env.
CMD ["env"]
