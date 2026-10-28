FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/pahredar ./cmd/pahredar
# Empty data dir, copied with nonroot ownership so the named volume inherits it.
RUN mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/pahredar /pahredar
COPY --from=build --chown=65532:65532 /out/data /var/lib/pahredar
EXPOSE 8080
ENTRYPOINT ["/pahredar"]
CMD ["serve"]
