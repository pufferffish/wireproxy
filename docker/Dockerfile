FROM golang:alpine AS go-build

RUN apk --no-cache add --update git
RUN git clone https://github.com/octeep/wireproxy.git
RUN cd ./wireproxy && go build ./cmd/wireproxy


FROM alpine:latest

RUN apk upgrade
COPY --from=go-build /go/wireproxy/wireproxy /usr/bin/

VOLUME [ "/etc/wireproxy"]
ENTRYPOINT [ "/usr/bin/wireproxy", "--config", "/etc/wireproxy/config" ]
