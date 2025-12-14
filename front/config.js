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
            url: 'http://192.168.31.44:9528'
        },
        {
            name: 'prod',
            value: 'prod',
            url: 'http://192.168.31.44:9527'
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
    ]
}
