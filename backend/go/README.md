# 说明

## 生成自己的config.yaml

根据`config.yaml.sample`生成自己的`config.yaml.sample`


## 反向代理

如果是nginx反向代理，需要关闭缓存，这样才能实时输出脚本运行过程：

```conf
  # nginx conf
  proxy_buffering off;              # 禁用缓冲
  proxy_cache off;                  # 禁用缓存
  proxy_request_buffering off;      # 禁用请求缓冲
  proxy_set_header X-Accel-Buffering no;
  proxy_read_timeout 300s;
```

