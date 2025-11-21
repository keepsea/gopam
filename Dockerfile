# --- 构建阶段 ---
FROM golang:1.23-alpine AS builder

# 安装 SQLite 编译所需的依赖
RUN apk add --no-cache gcc musl-dev

WORKDIR /app

# 利用 Docker 缓存机制，先下载依赖
COPY go.mod go.sum ./
RUN go mod download

# 复制源码并编译
COPY . .
# -ldflags="-w -s" 用于减小二进制体积
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-w -s" -o server cmd/server/main.go

# --- 运行阶段 ---
FROM alpine:latest

# 安装基础库和时区数据 (国内服务器必备)
RUN apk add --no-cache ca-certificates tzdata libc6-compat

WORKDIR /app

# 从构建阶段复制二进制文件
COPY --from=builder /app/server .

# 创建数据目录 (用于挂载 SQLite 数据库)
RUN mkdir -p /app/data

# 暴露端口
EXPOSE 8080

# 启动命令
CMD ["./server"]