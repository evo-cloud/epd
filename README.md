# Edge Proxy Daemon

This is a TCP reverse proxy for edge services behind firewalls.

## How It Works

The Edge Proxy Daemon must run somewhere it's able to open a TCP port on the network
that services are being exposed to (e.g. Internet). The edge services connect to
this proxy via SSH remote port forwarding. Here's an example:

- Run Edge Proxy Daemon on Internet, with DNS name epd.example.com;
- A web server is running behind firewall, and it's listening on `localhost:8080`;
- On the same machine as the web server is running, run `ssh -N -R www.example.com:80:localhost:8080 user@epd.example.com`

Now open the browser to access `http://www.example.com`, it should reach the web server running behind the firewall.
The Edge Proxy Daemon doesn't expose the exact port requested by the SSH client,
instead, it opens a random port on localhost, and relies on a endpoint setup script
to configure another reverse proxy for forwarding the connection on the requested DNS to this local port.

## Usage

Launch `epd` without arguments to use default configurations:

- `-addr=:2022`: listen on `:2022` as SSH server address;
- Use host keys from `/etc/ssh`;
- Use `~/.ssh/authorized_keys` for authorized keys;
- `-bind-addr=localhost`: open random TCP port as requested on `localhost`;

In addition to that, specifying `-endpoint-exec=PROGRAM` to use `PROGRAM` for setting up a DNS based reverse proxy.

For example, when using [traefik](https://github.com/containous/traefik), a shell script can be used to configure it
for forwarding the request on a specific DNS to a localhost port.
The `PROGRAM` is invoked as:

```
PROGRAM open|close hostname local-port
```

When `local-port` is opened for `hostname` (request on the client side as `ssh -R hostname:anyport:host:port`),
`open` is used.
When the forwarding request is canceled, `close` is used.
