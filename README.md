# guardi-cli

Why? Firstly we should be sure that AI write exactly what we need without any exploits.

This library provide development utility for understand what exactly doing AI written service.

In main case we need AB tests, then we need guardi DNS
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

# dev
Change resolve.conf, then `cargo run`

```
echo nameserver 127.0.0.1 > /etc/resolv.conf
echo nameserver 192.168.65.7 > /etc/resolv.conf
```