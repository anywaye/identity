ARG GO_VERSION=1.26

FROM golang:${GO_VERSION} AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOOS=linux
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG SERVICE_NAME=identity
RUN go build -trimpath -ldflags="-s -w" -o /out/service ./cmd/${SERVICE_NAME}
RUN go build -trimpath -ldflags="-s -w" -o /out/identity-staff ./cmd/identity-staff

FROM gcr.io/distroless/static-debian12:nonroot AS runtime
WORKDIR /app
COPY --from=build /out/service /app/service
COPY --from=build /out/identity-staff /app/identity-staff
COPY --from=build /out/service /app/bin/migrate
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app/service"]
