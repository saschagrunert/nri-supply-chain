FROM golang:1.26.5@sha256:3aff6657219a4d9c14e27fb1d8976c49c29fddb70ba835014f477e1c70636647 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /nri-supply-chain ./cmd/nri-supply-chain/

FROM gcr.io/distroless/static-debian13:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6
LABEL org.opencontainers.image.title="nri-supply-chain" \
      org.opencontainers.image.description="NRI plugin for container supply chain attestation verification" \
      org.opencontainers.image.source="https://github.com/saschagrunert/nri-supply-chain" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /nri-supply-chain /usr/local/bin/nri-supply-chain
ENTRYPOINT ["/usr/local/bin/nri-supply-chain"]
