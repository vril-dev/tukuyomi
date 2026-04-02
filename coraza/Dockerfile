FROM golang:1.26.0-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY src .
RUN go mod tidy
RUN go mod download

RUN go build -o server /app/cmd/server

FROM alpine:3.19

WORKDIR /app

COPY --from=builder /app/server .

EXPOSE 9090

CMD ["/app/server"]
