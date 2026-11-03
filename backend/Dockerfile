FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/pahredar ./cmd/pahredar
# Empty data dir, copied with nonroot ownership so the named volume inherits it.
RUN mkdir -p /out/data

# Nuclei is bundled for the optional active (intrusive) endpoint scanner. It
# is only invoked when SCAN_ACTIVE_ENABLED=true; its presence alone changes
# nothing. Pinned by version and verified by SHA-256.
ARG TARGETARCH
RUN apk add --no-cache unzip
RUN NUCLEI_VERSION=3.11.1 && \
    case "$TARGETARCH" in \
      amd64) SUM=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6 ;; \
      arm64) SUM=8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07 ;; \
      *) echo "unsupported arch $TARGETARCH" && exit 1 ;; \
    esac && \
    wget -q -O /tmp/n.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip" && \
    echo "${SUM}  /tmp/n.zip" | sha256sum -c - && \
    unzip -o /tmp/n.zip -d /out nuclei
# Nuclei templates (data, run by the sandboxed engine), pinned by tag.
RUN NT_VERSION=10.5.0 && mkdir -p /out/nuclei-templates &&     wget -q -O /tmp/nt.tgz "https://codeload.github.com/projectdiscovery/nuclei-templates/tar.gz/refs/tags/v${NT_VERSION}" &&     tar xzf /tmp/nt.tgz -C /out/nuclei-templates --strip-components=1

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/pahredar /pahredar
COPY --from=build /out/nuclei /usr/local/bin/nuclei
COPY --from=build /out/nuclei-templates /opt/nuclei-templates
COPY --from=build --chown=65532:65532 /out/data /var/lib/pahredar
EXPOSE 8080
ENTRYPOINT ["/pahredar"]
CMD ["serve"]
