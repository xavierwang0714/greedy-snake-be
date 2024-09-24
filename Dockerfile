FROM golang:latest
LABEL authors="Xavier Wang"

# 安装 Go
RUN yum -y update && yum -y install golang

# 设置工作目录
WORKDIR /go/src/app

# 复制当前目录下的所有文件到工作目录
COPY . .

# 设置 Go 环境变量
ENV GOPATH /go
ENV PATH=$PATH:$GOPATH/bin

# 安装依赖
RUN go mod download

# 编译
RUN go build -o main .

# 运行
CMD ["./main"]