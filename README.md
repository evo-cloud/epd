# Secure Port Forwarder

This is a remote port forwarder based on SSH protocol (`ssh -R`).
It only supports remote port forwarding, but not the rest of SSH features (no session/channel is supported),
so it's safer than running a full featured SSH server on a public network.

With Secure Port Forwarder running on a public network,
a server behind a firewall can be exposed to the public network using:

```shell
ssh -N -R www.example.com:80:localhost:8080 user@spf.example.com
```

Here assuming Secure Port Forwarder is running on `spf.example.com` on regular SSH port `22`,
and the server behind the firewall is running on `localhost:8080`.
The `ssh` command asks Secure Port Forwarder to forward `www.example.com:80` and rely it to `localhost:8080`.

However Secure Port Forwarder doesn't exposing the specified DNS and port to the public network.
Instead, it only opens a random TCP port on `localhost` and forwards connections to the SSH client.
User must provide an endpoint setup script for setting up `www.example.com:80` on some proxy server
(e.g. [traefik](https://github.com/containous/traefik)).

## Usage

Launch `spf` without arguments to use default configurations:

- `-addr=:2022`: listen on `:2022` as SSH server address;
- Use host keys from `/etc/ssh`;
- Use `~/.ssh/authorized_keys` for authorized keys;
- `-bind-addr=localhost`: open random TCP port as requested on `localhost`;

In addition to that, specifying `-setup-cmd=PROGRAM` to use `PROGRAM` for setting up a DNS based reverse proxy.

For example, when using [traefik](https://github.com/containous/traefik), a shell script can be used to configure it
for forwarding the request on a specific DNS to a localhost port.
The `PROGRAM` is invoked as:

```
PROGRAM open|close public-host:public-port local-host:local-port
```

- `open` is used to ask the script to start forwarding from `public-host:public-port` to `local-host:local-port`;
- `close` is used to ask the script to stop forwarding from `public-host:public-port`.

According to `-bind-address=A.B.C.D` when launching `spf`, and the SSH client command line, e.g.

```shell
ssh -N -R www.example.com:80:localhost:8080 user@spf.example.com
```

- `public-host:public-port` is `www.example.com:80`;
- `local-host:local-port` is `A.B.C.D:port` where the `port` is a random port opened by `spf`.
