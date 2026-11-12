FROM golang:1.27.3@sha256:e519d3b0a5b285e5aa53ab9eef02bc6bbb9cb04608389b743a136a9ce75f0d1e AS build
WORKDIR /src
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -mod=vendor -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /nri-supply-chain ./cmd/nri-supply-chain/

FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
LABEL org.opencontainers.image.title="nri-supply-chain" \
      org.opencontainers.image.description="NRI plugin for container supply chain attestation verification" \
      org.opencontainers.image.source="https://github.com/saschagrunert/nri-supply-chain" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /nri-supply-chain /usr/local/bin/nri-supply-chain
ENTRYPOINT ["/usr/local/bin/nri-supply-chain"]
