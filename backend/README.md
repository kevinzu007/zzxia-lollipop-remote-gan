# 说明

## setup

### 生成自己的config.yaml

根据`config.yaml.sample`生成自己的`config.yaml.sample`


### 反向代理

如果是nginx反向代理，/hook/需要关闭缓存，这样才能实时输出脚本运行过程：

```conf
# nginx conf
  proxy_pass http://backend:9527;
  # 后端记录客户实际ip
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  # shell命令实时输出
  proxy_buffering off;              # 禁用缓冲
  proxy_cache off;                  # 禁用缓存
  proxy_request_buffering off;      # 禁用请求缓冲
  proxy_set_header X-Accel-Buffering no;
  proxy_read_timeout 300s;
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

4 deploy body ：
     {
         "do": "deploy",
         "action": "help|list|docker|web",
         "Extra": "",
         "projects": [
             "pj1",
             "pj2",
             "pj3"
         ]
     }

5 docker-cluster-service-deploy body ：
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

7 web-release body ：
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


## 测试 api

### 测试 /gitlab/hook

#### 要点：

> git commit msg包含信息:.
> 全部： {env=dev|stag|prod|其他,do=build|gogogo,skiptest=yes,version=5.5,gray=yes}
> 最少： 如果(GITLAB_GIT_COMMIT_ENV_CHECK: "YES")，则{env=dev|stag|prod|其他} ；如果(GITLAB_GIT_COMMIT_ENV_CHECK: "NO")，则可以不包含任何信息    #-- 默认：do=gogogo

#### gitlab上设置：

1. 设置gitlab中项目的webhooks，比如 Secret token：1234567890zxc ; 网址：http://127.0.0.1:9527/hook/gitlab
2. git commit信息包含上面信息，等待看结果

#### curl方式测试：

curl  -X POST  \
          -H "Content-Type: application/json"  \
          -H "X-Gitlab-Event: Push Hook"  \
          -H "X-Gitlab-Token: 1234567890zxc"  \
          http://127.0.0.1:9527/hook/gitlab  \
          -d  @./jianguoyun/IT/python-webhook/gitlab-push-body.json


### 测试 /hand/hook

0  token获取（示例： 用户名：kevin，密码：123456）：
curl -X POST http://127.0.0.1:9527/get/token  \
   -H "user: kevin"  \
   -H "sec: $(echo -n 'kevin123456' | sha1sum | awk '{print $1}')"  \
   -v

TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Njc4NzA4NzUsImlhdCI6MTc2Nzg0MjA3NSwidXNlcm5hbWUiOiJrZXZpbiJ9.O-1chPRtktFDGYL5BAmkFn3WkVVWnLZt4QvutASA1ZM"

1  header方式：
curl -X POST http://127.0.0.1:9527/hook/hand \
  -H "Content-Type: application/json" \
  -H "token: ${TOKEN}" \
  -d '{"do": "build", "action": "help", "category": "test", "projects": ["aa"], "extra": "--abc ^aa$"}'

2  body方式：
curl -X POST http://127.0.0.1:9527/hook/hand \
  -H "Content-Type: application/json" \
  -b "auth_token=${TOKEN}" \
  -d '{"do": "build", "action": "help", "category": "test", "projects": ["aa"], "extra": "--abc ^aa$"}'


### 测试 /get/list/...

0  token获取（示例： 用户名：kevin，密码：123456）：
curl -X POST http://127.0.0.1:9527/get/token  \
   -H "user: kevin"  \
   -H "sec: $(echo -n 'kevin123456' | sha1sum | awk '{print $1}')"  \
   -v

TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Njc4NzA4NzUsImlhdCI6MTc2Nzg0MjA3NSwidXNlcm5hbWUiOiJrZXZpbiJ9.O-1chPRtktFDGYL5BAmkFn3WkVVWnLZt4QvutASA1ZM"

1  /get/list/project
curl -X GET  http://127.0.0.1:9527/get/list/project  \
  -H "Content-Type: application/json"  \
  -H "token: ${TOKEN}"

2  /get/list/docker-cluster-service
同上

3  /get/list/nginx
同上



