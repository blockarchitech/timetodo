FROM golang:1.23 AS builder

# timetodo
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /timetodo -ldflags="-s -w" -tags timetzdata .

# UI
FROM node:20 AS ui-builder
WORKDIR /ui
COPY ui/package*.json ./
RUN npm install
COPY ui/ .
RUN npm run build

FROM alpine:latest
RUN apk add --no-cache tzdata
COPY --from=builder /timetodo /timetodo
COPY --from=ui-builder /ui/dist /public
EXPOSE 8080
ENTRYPOINT ["/timetodo"]