FROM golang:1.26.5-alpine3.24 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /main .

FROM alpine:3.24.1
RUN apk add --no-cache tzdata ca-certificates
COPY --from=builder /main /usr/bin/main
ENTRYPOINT ["/usr/bin/main"]
CMD ["-c", "/etc/config.json"]
