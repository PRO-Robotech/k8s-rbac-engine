FROM golang:1.25-alpine AS builder

WORKDIR /workspace

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/
COPY pkg/      pkg/

ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/rbac-engine ./cmd/rbac-engine

FROM gcr.io/distroless/static:nonroot

USER 65532:65532

COPY --from=builder /out/rbac-engine /rbac-engine

EXPOSE 8080 8081

ENTRYPOINT ["/rbac-engine"]
