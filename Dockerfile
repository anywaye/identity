# identity — the service image.
#
#   docker build -t identity .
#   docker build --build-arg SERVICE_NAME=identity -t identity .
#
# The two-stage, CGO_ENABLED=0, distroless-nonroot shape is the kit Go template
# (kit/docker/Dockerfile.go). The notes there are the contract:
#
#   - Two stages, always. The builder carries the Go toolchain; the runtime does
#     not. An image with a compiler in it is an image with a supply chain in it.
#   - CGO_ENABLED=0 makes the binary static, which is what allows the final
#     stage to be distroless/static rather than a debian with libc in it.
#     identity needs no cgo: pgx is pure Go and DNS resolution is not on the
#     request path.
#   - nonroot, not root. The distroless nonroot user is uid 65532. There is no
#     shell in this image, so a compromised process cannot curl-and-pipe.
#   - The build context is the repository root, so `COPY go.mod go.sum ./` sees
#     the manifests and the dependency layer caches until they change.
ARG GO_VERSION=1.26

FROM golang:${GO_VERSION} AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOOS=linux
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG SERVICE_NAME=identity
RUN go build -trimpath -ldflags="-s -w" -o /out/service ./cmd/${SERVICE_NAME}
# The staff operator command ships in the SAME image, as a second static
# binary. It is never the server: ENTRYPOINT below stays /app/service, and a
# deployment runs it as a one-shot Job with an overridden command (see the
# staff section of README.md). Building it here rather than in a second image
# means the grant tool and the service are always the same build — a staff
# column written by a binary from another commit is a schema the service has
# not reviewed.
RUN go build -trimpath -ldflags="-s -w" -o /out/identity-staff ./cmd/identity-staff

FROM gcr.io/distroless/static-debian12:nonroot AS runtime
WORKDIR /app
COPY --from=build /out/service /app/service
COPY --from=build /out/identity-staff /app/identity-staff
USER nonroot:nonroot
EXPOSE 8080
# The service is stateless: the connection pool is opened lazily and closed on
# SIGTERM, so there is nothing to flush to disk and no volume to mount.
ENTRYPOINT ["/app/service"]
