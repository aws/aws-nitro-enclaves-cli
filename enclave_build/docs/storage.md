# Image Local Storage

When building an enclave image using the Docker daemon, the image is pulled and stored in the
Docker storage (place in the filesystem where images pulled from remote registries are saved locally).
We want to implement the same functionality when choosing to build an OCI image.
The resulted storage follows the [OCI specification](https://github.com/opencontainers/image-spec),
allowing tools like `linuxkit` to use it as its own cache, and also adding images from OCI archive
with the same format.

To ease the interactions with the image details, the storage structure holds the config of the
image used to build the EIF. This prevents unnecessary file reads.

## Structure

The root folder of the storage is either `${XDG_DATA_HOME}/.aws-nitro-enclaves-cli/container_storage`,
or, if `XDG_DATA_HOME` is not set, `${HOME}/.local/share/.aws-nitro-enclaves-cli/container_storage`
is used.

The storage holds common components used by all images (index file, layout file, blobs folder) and
individual items specific to the image named blobs (manifest, config file, layers). A possible
storage structure can look like this:

```
storage_dir/
|________index.json   -> points to the manifest blob file for each image (maps image reference to manifest digest)
|________oci-layout
|            blobs/sha256/
|            |_______98806831de537d56f19b4b3cbf6ed80187374a1521a18d2d0c5f8a0e3962b2ae -> manifest_hash points to config and layers
|            |_______feb5d9fea6a5e9606aa995e879d862b825965ba48de054caab5ef356dc6b3412 -> config_hash
|            |_______2db29710123e3e53a794f2694094b9b4338aa9ee5c40b930cb8063a1be392c54 -> layer_hash
```

### Examples

To better understand the storage structure and how the index and manifest point to other files, we
can follow a `hello-world` image example.

#### Index

index.json
```
{
  "schemaVersion": 2,
  "manifests": [
    {
      "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
      "size": 425,
      "digest": "sha256:98806831de537d56f19b4b3cbf6ed80187374a1521a18d2d0c5f8a0e3962b2ae",
      "annotations": {
        "org.opencontainers.image.ref.name": "docker.io/test-oci:hello"
      }
    }
  ]
}
```

As we can see, the index holds one manifest entry, for one image stored. The number of manifests
increases with each newly stored image. The manifest hash points us to the manifest blob.

#### Layout file

oci-layout:
```
{"imageLayoutVersion":"1.0.0"}
```

This file simply defines the OCI image layout version we are using.

#### Manifest

98806831de537d56f19b4b3cbf6ed80187374a1521a18d2d0c5f8a0e3962b2ae
```
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
  "config": {
    "mediaType": "application/vnd.docker.container.image.v1+json",
    "digest": "sha256:feb5d9fea6a5e9606aa995e879d862b825965ba48de054caab5ef356dc6b3412",
    "size": 1469
  },
  "layers": [
    {
      "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
      "digest": "sha256:2db29710123e3e53a794f2694094b9b4338aa9ee5c40b930cb8063a1be392c54",
      "size": 2479
    }
  ]
}
```

The manifest is our guide for a particular image. It tells us which components among the blobs
belong to the image it defines. It tells us the digest of the content for the config file and each
layer. With this information we can search the blobs.

#### Config

The configuration file defines the behavior of the image inside the container, platform
dependencies and interaction with the filesystem composed from the layers. Nitro CLI's usage of
the storage should not be concerned with the contents of this file (excepting UTF-8 and digest
validation).

#### Layers

Layers are serialized filesystem changes that go on top of each other, starting from the base
filesystem we create the image with. The file has binary content that, from Nitro CLI's point of
view, just has to obey the content digest in the manifest.

## Operations

The operations offered by the `storage` module are as follows:

### Create

When building our first image, the storage does not exist. This operation creates, prior to
storing an image, an empty storage. It contains the storage root folder and a blobs folder. Also
at this point, the config of the current image is not yet loaded in the memory.

### Store

This is the operation which adds an image to the storage. It is called on an empty storage or after
a fetch fails when searching for the image. After pulling the image and extracting its details, its
manifest entry is added to the index and the blobs are written, each to their file.

### Fetch details

This operation returns the details of an image (image name, config digest and the config itself).
These details are saved in the memory as the config of the image we are currently using to build
the EIF. If a fetch was performed before, the config is already loaded and we can just return it.
No other file read is needed.

When we fetch an image without the config already loaded, we want to also check that it is stored
correctly (or stored at all). The validation starts from the index file. It should contain our
image's reference and the digest of the manifest. If fields are missing or the JSON structure does
not comply, an error is returned.

The validation continues with the manifest. As we did with the index, we validate the structure and
get the digests for the config and blobs to later check them as well. We also check that the
content of the manifest matches its digest from the file name.

The config validation simply checks that a file with its content digest exists and the content is
UTF-8 formatted. The file name is also validated against the content hash.

Having a list of the layers' digest from the manifest, we go through each of them to get access to
the blob files. By hashing each of the files and comparing the result with the initial digest, we
validate the layers as well.


### Get root folder

So we can get access to the storage contents outside the `storage` module (in our case for
`linuxkit`), we want to be able to return the location of the storage files. The module returns
the root folder of the storage, as decided by the values of the environment variables
`XDG_DATA_HOME` or `HOME`.

## Workflow

To see how these operations fit with each other and the structure as well, let's explore the common
workflow:

1. Given an image name we want to build an EIF
2. Perform the first fetch:
  - Check if the config of the current image is loaded. If it is, just return the image details
  built from this config.
  - If there is no config, read the files and perform the validation while searching for the
  image files.
  - If the validation hasn't failed, return the config.
3. If the fetch failed (storage empty, missing our image, or malformed), pull the image from the
remote registry, store its contents and load the config.
4. A second fetch (for the inspect) returns the image details using the config from the memory
without additional steps.

