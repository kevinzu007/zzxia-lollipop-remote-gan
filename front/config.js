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
    projectList: [
        { category: 'html', name: 'gan' },
        { category: 'python', name: 'gan-api' },
        { category: 'product', name: 'nacos-server' },
        { category: 'product', name: 'neo4j' },
        { category: 'product', name: 'fluentd' },
        { category: 'dockerfile', name: 'my-oracle-java-8' },
        { category: 'java', name: 'gc-common' },
        { category: 'java', name: 'gc-gray' },
        { category: 'java', name: 'gc-auth-service' },
        { category: 'java', name: 'gc-monitor' },
        { category: 'node', name: 'gc-common-front' },
        { category: 'node', name: 'gc-platform-node' },
        { category: 'node', name: 'gc-agent-front' },
        { category: 'node', name: 'gc-fastprotect-front' }
    ],
    microServices: [
        { category: 'microservice', name: 'child-api' },
        { category: 'microservice', name: 'child-manage-api' },
        { category: 'microservice', name: 'child-cosyvoice' }
    ],
    webProjects: [
        { category: 'web', name: 'child-manage-front' },
        { category: 'web', name: 'child-h5-front' },
        { category: 'web', name: 'child-game-front' },
        { category: 'web', name: 'child-pen-h5-front' }
    ],
    actions: {
        'build': ['default', 'help', 'list'],
        'build-parallel': ['default', 'help', 'list'],
        'deploy': ['help', 'list', 'docker', 'web'],
        'gogogo': ['default', 'help', 'list'],
        'docker-cluster-service-deploy': ['help', 'list', 'list-run', 'create', 'modify', 'update', 'rollback', 'scale', 'rm', 'status', 'detail', 'logs'],
        'web-release': ['help', 'list', 'release', 'rollback'],
        'docker-image-search': ['default', 'help', 'list']
    }
}
