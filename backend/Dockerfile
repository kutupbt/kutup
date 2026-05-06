FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download

RUN go install github.com/swaggo/swag/cmd/swag@v1.8.1

COPY . .
RUN swag init -g main.go
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /kutup-server .

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /kutup-server /kutup-server

EXPOSE 3000
ENTRYPOINT ["/kutup-server"]
