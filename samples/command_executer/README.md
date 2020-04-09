# command-executer

An application that can run either as a server or a client. When running as a
server, it listens on a port for commands and executes them afterwards, sending
the output back to the client. When running as a client, it connects to the
above mentioned port, sends commands and waits for the reply (unless --no-wait
is used). The command-executer is useful for executing shell commands inside
the enclave and sending/receiving files to/from the enclave.

It replaces the old nc-vsock we used in the past (which we haven't bothered to
remove yet).

## Building

```
	$ cargo build
```

## Running

1. Build the project (see above).

2. Use the Dockerfile in resources/ either as an example or as is
and build an EIF.

```
	$ export NITRO_CLI_BLOBS=$(realpath ../../blobs/)
	$ nitro-cli build-enclave --docker-dir "./resources" --docker-uri mytag --output-file command-executer.eif
```

_NOTE: these steps can either be done on your local machine or on the EC2
instance your going to launch the enclave._

3. Copy __both__ the EIF __and__ the command-executer binary to the EC2
instance you are about to run an enclave on.

4. Launch an enclave with the EIF containing command-executer.

```
	$ ./nitro-cli run-enclave --cpu-count 4 --memory 2048 --eif-path command_executer.eif
	Start allocating memory...
	Running on instance CPUs [1, 5, 2, 6]
	Started enclave with enclave-cid: 16, memory: 2048 MiB, cpu-ids: [1, 5, 2, 6]
	Sending image to cid: 16 port: 7000
	{
	  "EnclaveID": "i-08aa8a2f7bff2ff99_enc103923520469154997",
	  "EnclaveCID": 16,
	  "NumberOfCPUs": 4,
	  "CPUIDs": [
	    1,
	    5,
	    2,
	    6
	  ],
	  "MemoryMiB": 2048
	}
```

5. Use the command-executer to send shell commands to the enclave

```
	$ ./command-executer run --cid 16 --port 5005 --command "whoami"
```

6. Use the command-executer to send files to the enclave (e.g. binaries you built in the instance)

```
	$ ./command-executer send-file --cid 16 --localpath "./stress-ng" --port 5005 --remotepath "/usr/bin/stress-ng"
```
