FROM golang:1.25.0-alpine AS build

WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/fault-fixture ./cmd/fault-fixture

FROM scratch

COPY --from=build /out/fault-fixture /fault-fixture
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=2s --timeout=1s --start-period=1s --retries=3 CMD ["/fault-fixture", "-healthcheck", "-healthcheck-url", "http://127.0.0.1:8080/health"]
ENTRYPOINT ["/fault-fixture", "-listen", ":8080"]
