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
#   - The image CARRIES ITS OWN SCHEMA. `migrations/*.sql` are embedded into the
#     binary (migrations/embed.go), so `identity migrate` — the same binary, at
#     /app/bin/migrate as well as /app/service — applies them in place, with no
#     shell, no `psql` and no goose CLI in the artifact. That is what makes the
#     substrate's one-shot migrate Job possible at all; the entrypoint above is
#     still the server and still never migrates on boot.
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
# /app/bin/migrate IS THE SAME BINARY AS /app/service, COPIED A SECOND TIME, AND
# IT EXISTS FOR THE SUBSTRATE RATHER THAN FOR A PERSON.
#
# kit's `install_migrations` runs each service's migrate entrypoint at a path it
# already knows — `/app/bin/migrate` for identity (`migration_command_for` in
# templates/substrate/install.sh) — with no override, so that is the path that
# has to exist for a box to come up with a schema. The runtime stage is
# distroless, so it cannot be a shell script, and there is no `ln` and no `cp` to
# run in it at all.
#
# A SYMLINK WAS TRIED AND DOES NOT SURVIVE THE COPY. Measured against Docker
# 29.8.2 with a busybox stand-in for exactly these two lines:
#
#     FROM busybox AS build
#     RUN mkdir -p /out/bin && ln -s /bin/busybox /out/bin/migrate
#     FROM busybox
#     COPY --from=build /out/bin/migrate /app/bin/migrate
#     RUN ls -l /app/bin/migrate
#     -rwxr-xr-x 1 root root 1185328 /app/bin/migrate      # a regular file
#
# `COPY --from=<stage>` DEREFERENCES the link, so a link made in the builder
# arrives as a second copy of its target anyway. Saying that out loud is the
# honest form: ONE `go build`, TWO NAMES, and this COPY is what makes them the
# same bytes (two builds would be a migrator from another commit, which is the
# thing the staff binary's comment above refuses for the same reason).
#
# The dispatch is by the name the process was started under (`subcommand` in
# cmd/identity/main.go), which is what makes `/app/bin/migrate` the migrator and
# `/app/service` the server.
COPY --from=build /out/service /app/bin/migrate
USER nonroot:nonroot
EXPOSE 8080
# The service is stateless: the connection pool is opened lazily and closed on
# SIGTERM, so there is nothing to flush to disk and no volume to mount.
ENTRYPOINT ["/app/service"]
