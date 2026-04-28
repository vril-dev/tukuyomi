FROM golang:1.26.2-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN go build -o server /app/cmd/server
RUN CGO_ENABLED=0 go install github.com/maxmind/geoipupdate/v7/cmd/geoipupdate@v7.1.1

FROM alpine:3.19

WORKDIR /app

RUN apk add --no-cache bash curl python3 ca-certificates

COPY --from=builder /app/server .
COPY --from=builder /go/bin/geoipupdate /app/bin/geoipupdate

EXPOSE 9090

CMD ["/app/server"]
