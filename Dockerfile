# Start by building the application.
FROM golang:1.18 as build

WORKDIR /usr/src/wireproxy
COPY . .

RUN CGO_ENABLED=0 go build ./cmd/wireproxy

# Now copy it into our base image.
FROM gcr.io/distroless/static-debian11:nonroot
COPY --from=build /usr/src/wireproxy/wireproxy /usr/bin/wireproxy

VOLUME [ "/etc/wireproxy"]
ENTRYPOINT [ "/usr/bin/wireproxy" ]
CMD [ "--config", "/etc/wireproxy/config" ]
