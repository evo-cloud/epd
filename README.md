# Secure Port Forwarder

This is a remote port forwarder based on SSH protocol (`ssh -R`).
It only supports remote port forwarding, but not the rest of SSH features (no session/channel is supported),
so it's safer than running a full featured SSH server on a public network.

With Secure Port Forwarder running on a public network,
a server behind a firewall can be exposed to the public network using:

```shell
ssh -N -R https/www.example.com:localhost:8080 user@spf.example.com
```

Here assuming Secure Port Forwarder is running on `spf.example.com` on regular SSH port `22`,
and the server behind the firewall is running on `localhost:8080`.
The `ssh` command asks Secure Port Forwarder to forward `www.example.com:80` and rely it to `localhost:8080`.

However Secure Port Forwarder doesn't exposing the specified DNS and port to the public network.
Instead, it only opens a random TCP port on `localhost` and forwards connections to the SSH client.
User must provide an endpoint setup script for setting up `www.example.com:80` on some proxy server
(e.g. [traefik](https://github.com/containous/traefik)).

## Usage

Launch `spfd` without arguments to use default configurations:

- `-addr=:2022`: listen on `:2022` as SSH server address;
- Use host keys from `/etc/ssh`;
- Use `~/.ssh/authorized_keys` for authorized keys;
- `-bind-addr=localhost`: open random TCP port as requested on `localhost`;

In addition to that, specifying `-setup-cmd=PROGRAM` to use `PROGRAM` for setting up a DNS based reverse proxy.

For example, when using [traefik](https://github.com/containous/traefik), a shell script can be used to configure it
for forwarding the request on a specific DNS to a localhost port.
The `PROGRAM` is invoked as:

```
PROGRAM open|close tcp|sock ENDPOINT local-host:local-port
```

- `open` is used to ask the script to start forwarding from `ENDPOINT` to `local-host:local-port`;
- `close` is used to ask the script to stop forwarding from `ENDPOINT`.

`ENDPOINT` is defined for
- `tcp`: `public-host:public-port`
- `sock`: a unix socket path, it's recommended to be `scheme/DNS`, e.g. `https/example.com`. 

According to `-bind-address=A.B.C.D` when launching `spfd`, and the SSH client command line, e.g.

```shell
ssh -N -R https/www.example.com:localhost:8080 user@spf.example.com
```

It will call the setup program as

```
PROGRAM open sock https/www.example.com A.B.C.D:port
```

## The Client

`spfc` is a client to work with server-side `spfd` as an HTTP reverse proxy.
It watches dynamic backend states and exposes/unexposes endpoints accordingly.
The currently supported backend states providers are:

- `files`: Watches a list of directories (not sub-directories) and loads backend configurations from text files;
- `k8s`: Run `spfc` as a Kubernetes controller which watches `Service` resources with annotation `spf.evo-cloud/endpoint` and exposes the annotation value as the endpoint on the server side.

### Files Provider

The format of a file containing backend states is:

```
ID ENDPOINT BACKEND-URL
```

E.g.

```
a https/a.example.com http://localhost:8080
```

Empty lines and lines starting with `#` are ignored.
All the lines from all discovered files are merged to create the final list of backend states.
Use the following command line flags to enable this provider:

- `--files-dirs`: a semi-colon separated list of directory paths to watch for files and this must be specified to enable this provider;
- `--files-glob`: a pattern to filter file names. The default value is `*` (matching all files).

### Kubernetes Provider

Simply put `--k8s` on the command line to enable this provider.
It watches `Service` resource with annotation `spf.evo-cloud/endpoint`.
The value of the annotation is used as `ENDPOINT` on the server side.
The format should be `SCHEME/DNS`. `SCHEME` can be `https` or `http`.

The first `Port` in the `Service` will be used as backend server port.
If no `Port` is present, default HTTP port `80` will be used.
