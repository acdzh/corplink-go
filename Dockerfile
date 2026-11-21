# syntax=docker/dockerfile:1

FROM golang:1.27-bookworm AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOOS=linux
# 允许构建时覆盖模块代理（国内网络建议 goproxy.cn）
ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/corplink ./apps/cli

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/corplink /usr/local/bin/corplink
USER nonroot:nonroot
VOLUME ["/data"]
EXPOSE 3710 13140
ENTRYPOINT ["/usr/local/bin/corplink"]
CMD ["serve", "-config", "/data/config.json", "-proxy", "0.0.0.0:3710", "-panel", "0.0.0.0:13140"]
