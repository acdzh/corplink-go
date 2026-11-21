# syntax=docker/dockerfile:1

# 运行镜像。gcr.io 拉不动时改用镜像站：
#   --build-arg RUNTIME_IMAGE=gcr.m.daocloud.io/distroless/static-debian12:nonroot
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot

# 多架构构建：docker buildx 会注入 TARGETOS / TARGETARCH，
# 编译阶段固定跑在构建机架构上，产出的二进制按目标架构交叉编译。
FROM --platform=$BUILDPLATFORM golang:1.27-bookworm AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
ENV CGO_ENABLED=0
# 允许构建时覆盖模块代理（国内网络建议 goproxy.cn）
ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/corplink ./apps/cli

FROM ${RUNTIME_IMAGE}
COPY --from=build /out/corplink /usr/local/bin/corplink
USER nonroot:nonroot
VOLUME ["/data"]
EXPOSE 3710 13140
ENTRYPOINT ["/usr/local/bin/corplink"]
CMD ["serve", "-config", "/data/config.json", "-proxy", "0.0.0.0:3710", "-panel", "0.0.0.0:13140"]
