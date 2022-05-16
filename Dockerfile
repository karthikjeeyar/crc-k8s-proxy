FROM registry.access.redhat.com/ubi8/go-toolset:1.17.7 as builder

WORKDIR /workspace

COPY go.mod .
COPY go.sum .

USER 0

RUN go mod download

COPY main.go .
COPY keycloak.go .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -o crc-k8s-proxy main.go keycloak.go

FROM registry.access.redhat.com/ubi8/ubi-minimal:8.6

USER 0

WORKDIR /workspace

COPY --from=builder /workspace/crc-k8s-proxy .

ENTRYPOINT [ "/workspace/crc-k8s-proxy" ]
