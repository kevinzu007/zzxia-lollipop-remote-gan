#!/bin/bash

# 在本地编译时添加 CGO_ENABLED=0，这样会生成一个完全静态链接的二进制文件，不依赖系统的 glibc

# 静态编译（不依赖 glibc）
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o lollipop-remote-gan-api main.go


