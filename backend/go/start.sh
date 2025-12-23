#!/bin/bash
# 启动脚本 - 指定配置文件路径

cd "$(dirname "$0")" || exit 1

# 设置配置文件路径
export CONFIG_FILE="./config.yaml"

# 启动服务器
./lollipop-remote-gan-api

