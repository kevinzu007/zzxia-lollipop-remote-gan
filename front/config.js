window.ganConfig = {
    envs: [
        {
            name: 'Default',
            value: 'default',
            url: 'http://127.0.0.1:9527'
        },
        {
            name: 'dev',
            value: 'dev',
            url: 'http://192.168.31.44:9527'
        },
        {
            name: 'stag',
            value: 'stag',
            url: 'http://yourdomain.com:9527'
        },
        {
            name: 'prod',
            value: 'prod',
            url: 'https://mtss-gan-api.mtshengsheng.com'
        }
    ],
    categories: ['', 'java', 'node', 'dockerfile'],
    actions: {
        'build': ['default', 'help', 'list'],
        'build-parallel': ['default', 'help', 'list'],
        'gogogo': ['default', 'help', 'list'],
        'deploy': ['help', 'list', 'docker', 'web'],
        'docker-cluster-service-deploy': ['help', 'list', 'list-run', 'create', 'modify', 'update', 'rollback', 'scale', 'rm', 'status', 'detail', 'logs'],
        'docker-image-search': ['default', 'help', 'list'],
        'web-release': ['help', 'list', 'release', 'rollback'],
        'gan': ['help', 'build', 'build-para', 'gogogo', 'deploy', 'deploy-docker', 'deploy-web', 'ngx-dns', 'ngx-root', 'ngx-conf', 'ngx-cert', 'ngx-cert-w', 'pg-b-r', 'aliyun-dns', 'godaddy-dns']
    }
}
