## Vsock Proxy

Implements a proxy server that runs on the parent instance and forwards vsock traffic from an enclave
to a TCP endpoint. It can be run independently or as a service.

### How to build

It is recommended to build the vsock_proxy binary from the root of the Nitro CLI
repository, using its Makefile target:

```
[aws-nitro-enclaves-cli]$ make vsock-proxy
```
This will create the build directory containing the release profile binary in
`aws-nitro-enclaves-cli/build/vsock_proxy/x86_64-unknown-linux-musl/release/vsock-proxy`

Another option for building is to use `cargo build` from the `vsock_proxy` directory.

### How to use

To see the help section, run the binary with `--help` option:
```
[aws-nitro-enclaves-cli]$ ./build/vsock_proxy/x86_64-unknown-linux-musl/release/vsock-proxy --help
Vsock-TCP proxy 
Vsock-TCP proxy

USAGE:
    vsock-proxy [FLAGS] [OPTIONS] <local_port> <remote_addr> <remote_port>

FLAGS:
    -h, --help    Prints help information
    -4, --ipv4    Force the proxy to use IPv4 addresses only.
    -6, --ipv6    Force the proxy to use IPv6 addresses only.

OPTIONS:
        --config <config_file>     YAML file containing the services that
                                   can be forwarded.
                                    [default: /etc/nitro_enclaves/vsock-proxy.yaml]
    -w, --num_workers <workers>    Set the maximum number of simultaneous
                                   connections supported. [default: 4]

ARGS:
    <local_port>     Local Vsock port to listen for incoming connections.
    <remote_addr>    Address of the server to be proxyed.
    <remote_port>    Remote TCP port of the server to be proxyed.

```

* `<local_port>`  
-> the vsock port on which the proxy will listen for connections from the enclave;

* `<remote_addr>`  
-> the address to which the enclave wants to connect; it can either be an IP address (e.g. 127.0.0.1),  
or it can be a domain name (e.g. localhost);

* `<remote_port>`  
-> the port from the remote machine specific to the service the enclave wants to access (e.g. 443)

For example, if the enclave wants to access the AWS KMS HTTPS endpoint in N. Virginia region, the proxy
could be started like this:

```
vsock-proxy 8000 kms.us-east-1.amazonaws.com 443
```
The local port number (in this case, 8000) can be any other port number greater than 3 that the enclave knows about.

#### Flags and options

* `-4, --ipv4`  
-> if the user wants to use only IPv4 addresses (either directly specified or translated
from a domain name); this is mutually exclusive with the `--ipv6` flag

* `-6, --ipv6`  
-> if the user wants to use only IPv6 addresses (either directly specified or translated
from a domain name); this is mutually exclusive with the `--ipv4` flag

* `--config <config_file`  
-> to limit the services that the vsock proxy can forward to, we use a configuration file that
contains an allowlist of accessible services; the default location of this file is `/etc/nitro_enclaves/vsock-proxy.yaml`;
we specify the format of this file in a later section

* `-w, --num_workers <workers>`  
-> several simultaneous connections can be proxied at a given time; to limit the amount of resources
available to the proxy process, a number of workers can be specified; the default number of workers
is 4

### Configuration file format

The configuration file is in YAML format. It should have a key, `allowlist`, and a corresponding list
of accepted endpoints.  
We define an accepted endpoint by two keys: `address` and `port`, and their corresponding values.  
A configuration file example can be found in `configs/vsock-proxy.yaml`.

### Vsock proxy service

After installing the Nitro CLI RPM, the vsock proxy can be run as a service using the following command:  
```
systemctl enable nitro-enclaves-vsock-proxy.service
```
The service files can be found in `service` directory. The proxy is ran using the default configuration
from `/etc/nitro_enclaves/vsock-proxy.yaml`, on local port 8000 and the AWS KMS endpoint corresponding to
the region of the instance.

You can use the following command to check the vsock proxy logs to diagnose connectivity issues.
```
journalctl -eu nitro-enclaves-vsock-proxy.service
```
To enable more detailed logging output, set the `RUST_LOG` environment variable to the `trace` log level in
the service file (e.g.`/usr/lib/systemd/system/nitro-enclaves-vsock-proxy.service`).
