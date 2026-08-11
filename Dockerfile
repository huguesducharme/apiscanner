FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod ./

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o apiscanner ./cmd/apiscanner

FROM alpine:latest

WORKDIR /root/

COPY --from=builder /app/apiscanner .

ENTRYPOINT ["./apiscanner"]