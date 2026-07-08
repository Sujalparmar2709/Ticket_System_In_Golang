FROM golang:1.22-alpine AS build

WORKDIR /app

COPY go.mod ./
COPY . ./

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/ticket-system .

FROM alpine:3.20

WORKDIR /app
COPY --from=build /out/ticket-system /app/ticket-system

EXPOSE 8080

ENV PORT=8080

CMD ["/app/ticket-system"]
