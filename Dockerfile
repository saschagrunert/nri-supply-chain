FROM golang:1.26.5 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /nri-supply-chain ./cmd/nri-supply-chain/

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /nri-supply-chain /usr/local/bin/nri-supply-chain
ENTRYPOINT ["/usr/local/bin/nri-supply-chain"]
