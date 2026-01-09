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


## body api 设计

     1 build body ：
     {
         "do": "build",
         "action": "default|help|list",
         "category": "java",
         "branch": "master",
         "skiptest": "yes",
         "force": "yes",
         "extra": "",
         "projects": [
             "pj1",
             "pj2",
             "pj3"
         ]
     }


     2 build-parallel body ：
     {
         "do": "build-parallel",
         "action": "default|help|list",
         "category": "java",
         "branch": "master",
         "skiptest": "yes",
         "force": "yes",
         "extra": "",
         "projects": [
             "pj1",
             "pj2",
             "pj3"
         ]
     }

     3 gogogo body ：
     {
         "do": "gogogo",
         "action": "default|help|list",
         "category": "java",
         "branch": "master",
         "skiptest": "yes",
         "force": "yes",
         "gray": "yes",
         "release-version": "5.5",
         "extra": "",
         "projects": [
             "pj1",
             "pj2",
             "pj3"
         ]
     }

     4 docker-cluster-service-deploy body ：
     {
         "do": "docker-cluster-service-deploy",
         "action": "help|list|list-run|create|modify|update|rollback|scale|rm|status|detail|logs",
         "force": "yes",
         "gray": "yes",
         "release-version": "5.5",
         "extra": "",
         "projects": [
             "pj1",
             "pj2",
             "pj3"
         ]
     }


     5 web-release body ：
     {
         "do": "web-release",
         "action": "help|list|release|rollback",
         "extra": "",
         "projects": [
             "pj1",
             "pj2",
             "pj3"
         ]
     }


     6 docker-image-search body ：
     {
         "do": "docker-image-search",
         "action": "default|help|list",
         "extra": "",
         "projects": [
             "pj1",
             "pj2",
             "pj3"
         ]
     }


## 测试 api

### 测试 /gitlab/hook

curl  -X POST  \
          -H "Content-Type: application/json"  \
          -H "X-Gitlab-Event: Push Hook"  \
          -H "X-Gitlab-Token: 1234567890zxc"  \
          https://mtss-gan-api.mtshengsheng.com/hook/gitlab  \
          -d  @./jianguoyun/IT/python-webhook/gitlab-push-body.json


### 测试 /hand/hook

1  token获取（示例： 用户名：kevin，密码：123456）：
curl -X POST https://mtss-gan-api.mtshengsheng.com/get/token  \
   -H "user: kevin"  \
   -H "sec: $(echo -n 'kevin123456' | sha1sum | awk '{print $1}')"  \
   -v

TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Njc4NzA4NzUsImlhdCI6MTc2Nzg0MjA3NSwidXNlcm5hbWUiOiJrZXZpbiJ9.O-1chPRtktFDGYL5BAmkFn3WkVVWnLZt4QvutASA1ZM"

2  header方式：
curl -X POST https://mtss-gan-api.mtshengsheng.com/hook/hand \
  -H "Content-Type: application/json" \
  -H "token: ${TOKEN}" \
  -d '{"do": "build", "action": "help", "category": "test", "projects": ["aa"], "extra": "--abc ^aa$"}'

3  body方式：
curl -X POST https://mtss-gan-api.mtshengsheng.com/hook/hand \
  -H "Content-Type: application/json" \
  -b "auth_token=${TOKEN}" \
  -d '{"do": "build", "action": "help", "category": "test", "projects": ["aa"], "extra": "--abc ^aa$"}'




