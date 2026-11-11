FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go index.html ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /myurls . \
 && mkdir /data && chown 65534:65534 /data

FROM scratch
COPY --from=build /myurls /myurls
COPY --from=build --chown=65534:65534 /data /data
USER 65534:65534
ENV DATA_FILE=/data/urls.json
EXPOSE 8080
VOLUME /data
HEALTHCHECK --interval=30s --timeout=5s CMD ["/myurls", "-health"]
ENTRYPOINT ["/myurls"]
