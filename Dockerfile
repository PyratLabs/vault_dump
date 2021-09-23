FROM golang:1.16-alpine AS builder

WORKDIR /build/vault_dump
COPY . .

RUN apk add --no-cache git make \
    && go mod download \
    && make linux-amd64 \
    && adduser -D -g '' vault_dump

FROM alpine:3.14

COPY --from=builder /build/vault_dump/build/vault_dump-linux-amd64 /usr/bin/vault_dump
COPY --from=builder /etc/passwd /etc/passwd

USER vault_dump
ENTRYPOINT [ "/usr/bin/vault_dump" ]
