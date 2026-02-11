FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git
RUN go install github.com/swaggo/swag/cmd/swag@latest 

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN swag init -g cmd/api/main.go --parseDependency

RUN CGO_ENABLED=0 GOOS=linux go build -o chameleon-auth-api ./cmd/api/main.go

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /app/chameleon-auth-api .

COPY --from=builder /app/docs ./docs

EXPOSE 8081

CMD ["./chameleon-auth-api"]
