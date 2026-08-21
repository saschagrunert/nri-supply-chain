FROM golang:1.27.0@sha256:65b6f280bf050ec5af12716857e8ea8439d694dbba8f31ceeb7630670071f2bb AS build
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
