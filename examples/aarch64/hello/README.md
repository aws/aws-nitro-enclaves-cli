## Nitro Enclaves Hello-World Example

This is a trivial hello-world example, intended to demonstrate building and
running your first Nitro Enclave.

When run, the enclave in this example will write a greeting message to the
enclave console every 5 seconds.

## Building

Nitro Enclave images are built from Docker container images. For the purpose
of this example, we'll use the included Dockerfile. From the root directory
of this example, build and tag the source container:

```bash
docker build -t hello-enclave:1.0 ./
```

Then, use the above Docker image tag to build the enclave image (`hello.eif`):

```bash
nitro-cli build-enclave --docker-uri hello-enclave:1.0 --output-file /tmp/hello.eif
```

## Running

Now that we have brand new enclave image, let's use `nitro-cli` to boot it up:

```bash
nitro-cli run-enclave --eif-path /tmp/hello.eif --cpu-count 2 --memory 128 --debug-mode
```

Note: we are running the enclave in debug mode in order to be able to access
      to its console and see our greeting.

We should now be able to connect to the enclave console and see our greeting:

```bash
nitro-cli console --enclave-id $(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
```
