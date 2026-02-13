# guardi-cli

Why? Firstly we should be sure that AI write exactly what we need without any exploits.

This library provide development utility for understand what exactly doing AI written service.

In main case we need e2e tests, then we need guardi DNS
We strictly check that service use only allowed hosts and block other.

Also this DNS can be directly runned inside production container

# examples
`guardi-cli curl http://google.com --allow google.com`
```
🛡️  Guardi: Network Monitoring Active
📡 Allowed domains: host.docker.internal,google.com
🟢 ALLOWED: google.com
```

`guardi-cli curl http://google.com --allow any.other.com`
```
🛡️  Guardi: Network Monitoring Active
📡 Allowed domains: host.docker.internal
🔴 BLOCKED: google.com
```

# example Dockerfile
```
FROM ubuntu:resolute
WORKDIR /app
RUN apt update && apt install curl -y
RUN curl https://github.com/guardi-dev/guardi-cli/releases/download/v0.0.1/guardi-cli-linux-amd64.tar.gz -LO
RUN tar -xzf guardi-cli-linux-amd64.tar.gz
CMD ./guardi-cli curl http://google.com --allow any.other.com
```

# example docker-compose.yml
```
guardi-cli-test:
  build: 
    context: .
    dockerfile: ./tmp/Dockerfile.guardi-cli
  dns:
    - 127.0.0.1
```

# development
Change resolve.conf, then `cargo run`

```
echo nameserver 127.0.0.1 > /etc/resolv.conf
echo nameserver 192.168.65.7 > /etc/resolv.conf
```
