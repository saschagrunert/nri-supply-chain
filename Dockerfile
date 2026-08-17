FROM golang:1.26.6@sha256:0d1d3a794be25f809dd2cb3160d8c73276c4056a9f8242a138e908ddeee7b6b6 AS build
WORKDIR /src
COPY . .
ARG VERSION=dev
ARG SOURCE_DATE_EPOCH=0
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
RUN CGO_ENABLED=0 go build -mod=vendor -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /nri-supply-chain ./cmd/nri-supply-chain/

FROM gcr.io/distroless/static-debian13:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6
LABEL org.opencontainers.image.title="nri-supply-chain" \
      org.opencontainers.image.description="NRI plugin for container supply chain attestation verification" \
      org.opencontainers.image.source="https://github.com/saschagrunert/nri-supply-chain" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /nri-supply-chain /usr/local/bin/nri-supply-chain
ENTRYPOINT ["/usr/local/bin/nri-supply-chain"]
