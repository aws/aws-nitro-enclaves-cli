## driver-bindings

This library provides Rust FFI bindings to Linux Nitro Enclaves driver
generated using [bindgen](https://crates.io/crates/bindgen).

The bindings exported by this crate are statically generated using header files
associated with a specific kernel version, and are not automatically synced with
the kernel version running on a particular host. The user must ensure that
specific structures, members, or constants are supported and valid for the
kernel version they are using.

Supported Linux versions:
  - x86_64
      - Amazon Linux 2 v4.14 kernel starting with kernel-4.14.198-152.320.amzn2.x86_64
      - Amazon Linux 2 v5.4 kernel starting with kernel-5.4.68-34.125.amzn2.x86_64
      - Amazon Linux 2 v5.10+ kernel (e.g. kernel-5.10.29-27.128.amzn2.x86_64)
      - Amazon Linux 2022 v5.10+ kernel (e.g. kernel-5.10.75-82.359.amzn2022.x86_64)
      - CentOS Stream v4.18+ kernel starting with kernel-4.18.0-257.el8.x86_64
      - Fedora v5.10+ kernel (e.g. kernel-5.10.12-200.fc33.x86_64)
      - openSUSE Tumbleweed v5.10+ kernel (e.g. kernel-default-5.10.1-1.1.x86_64)
      - Red Hat Enterprise Linux v4.18+ kernel starting with kernel-4.18.0-305.el8.x86_64
      - Ubuntu v5.4 kernel starting with linux-aws 5.4.0-1030-aws x86_64
      - Ubuntu v5.8 kernel starting with linux-aws 5.8.0-1017-aws x86_64
      - Ubuntu v5.11+ kernel (e.g. linux-aws 5.11.0-1006-aws x86_64)

  - aarch64
      - Amazon Linux 2 v4.14 kernel starting with kernel-4.14.252-195.483.amzn2.aarch64
      - Amazon Linux 2 v5.4 kernel starting with kernel-5.4.156-83.273.amzn2.aarch64
      - Amazon Linux 2 v5.10+ kernel starting with kernel-5.10.75-79.358.amzn2.aarch64
      - Amazon Linux 2022 v5.10+ kernel starting with kernel-5.10.75-82.359.amzn2022.aarch64
      - CentOS Stream v4.18 kernel starting with kernel-4.18.0-358.el8.aarch64
      - CentOS Stream v5.14+ kernel starting with kernel-5.14.0-24.el9.aarch64
      - Fedora v5.16+ kernel (e.g. kernel-5.16.5-200.fc35.aarch64)
      - Ubuntu v5.4 kernel starting with linux-aws 5.4.0-1064-aws aarch64
      - Ubuntu v5.13+ kernel starting with linux-aws 5.13.0-1012-aws aarch64

Generate bindings for a new Linux version:

```
bindgen --with-derive-default --allowlist-type "ne_.*" --allowlist-var "NE_ERR_.*" -o bindings.rs \
		/usr/src/kernels/$(uname -r)/include/uapi/linux/nitro_enclaves.h -- \
		-fretain-comments-from-system-headers -fparse-all-comments
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.0
