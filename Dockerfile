# 使用官方的 Go 镜像作为构建阶段
FROM golang:1.21 AS builder

# 设置工作目录
WORKDIR /var/deploy

# 将 go.mod 和 go.sum 文件复制到工作目录
COPY go.mod go.sum ./

# 下载依赖
RUN go mod download

# 将源代码复制到工作目录
COPY . .

# 编译应用程序
# 使用 CGO_ENABLED=0 和 GOOS=linux 生成静态链接的二进制文件
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o snake .

# 使用一个更小的基础镜像来运行应用程序
FROM alpine:latest

# 设置工作目录
WORKDIR /var/deploy

# 从构建阶段复制编译后的二进制文件
COPY --from=builder /var/deploy .

# 暴露应用程序运行的端口
EXPOSE 6673

# 运行应用程序
CMD ["/var/deploy/snake"]