# 说明

## 生成自己的config.yaml

根据`config.yaml.sample`生成自己的`config.yaml.sample`


## 反向代理

如果是nginx反向代理，需要关闭缓存，这样才能实时输出脚本运行过程：

```conf
# nginx conf
  # shell命令实时输出
  proxy_buffering off;              # 禁用缓冲
  proxy_cache off;                  # 禁用缓存
  proxy_request_buffering off;      # 禁用请求缓冲
  proxy_set_header X-Accel-Buffering no;
  proxy_read_timeout 300s;
  # 后端记录客户实际ip
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

