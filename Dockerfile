FROM golang:1.23 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /timetodo -ldflags="-s -w" .

FROM alpine:latest
COPY --from=builder /timetodo /timetodo
EXPOSE 8080
ENTRYPOINT ["/timetodo"]