# Build a static binary with the Go FIPS 140-3 cryptographic module compiled in.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOFIPS140=v1.0.0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

# Minimal, non-root runtime image: no shell, no package manager.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/server /server
ENV REQUIRE_FIPS=true ADDR=:8443
EXPOSE 8443
USER nonroot:nonroot
ENTRYPOINT ["/server"]
