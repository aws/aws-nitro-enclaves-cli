#[cfg(test)]
mod tests {
    use kvm_bindings::kvm_userspace_memory_region;
    use std::fs::{File, OpenOptions};
    use std::os::raw::c_ulong;
    use std::os::unix::io::AsRawFd;

    use nitro_cli::common::ExitGracefully;
    use nitro_cli::enclave_proc::resource_manager::{
        EnclaveHandle, EnclaveManager, MemoryRegion, ResourceAllocator, KVM_CREATE_VCPU,
        KVM_CREATE_VM, KVM_SET_USER_MEMORY_REGION,
    };

    use num_derive::FromPrimitive;

    const SAMPLE_EIF_PATH: &str = "./eifs/command_executer.eif";
    const ENC_HANDLE_INIT_FAULTY_DRIVER_ERR_STR: &str = "Failed to get enclave device descriptor.";

    #[derive(FromPrimitive)]
    enum DriverCmd {
        SetupTest = 0,
    }

    #[derive(FromPrimitive)]
    enum DriverTestCase {
        TestInvalidEncFd = 1,
        TestValidEncFd,
        TestInvalidMemReg,
        TestValidMemReg,
        TestInvalidVcpu,
        TestValidVcpu,
    }

    fn get_hugepagesize() -> u64 {
        let mem_info = procfs::Meminfo::new().ok_or_exit("Failed to read memory information");

        match mem_info.hugepagesize {
            Some(value) => value,
            None => procfs::page_size().ok_or_exit("Failed to read page size.") as u64,
        }
    }

    #[test]
    fn test_memory_region_init() {
        let mem_info = procfs::Meminfo::new().ok_or_exit("Failed to read memory information.");
        let total_hugepages_available = mem_info.hugepages_total;

        if let Some(total_hugepages_available) = total_hugepages_available {
            if total_hugepages_available > 0 {
                let region_size = 1 << 21;
                let mem_region_result = MemoryRegion::new(region_size);

                assert!(mem_region_result.is_ok());
            } else {
                let region_size = 1 << 20;
                let mem_region_result = MemoryRegion::new(region_size);

                assert!(mem_region_result.is_err());
                if let Err(err_str) = mem_region_result {
                    assert!(err_str.eq("Failed to map memory."));
                }
            }
        }
    }

    #[test]
    fn test_enclave_handle_init_faulty_driver() {
        let enc_mem = 32;
        let cpu_ids = vec![1, 3];

        let dev_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/nitro_enclaves")
            .ok_or_exit("Failed to open device file.");

        let rc = unsafe {
            libc::ioctl(
                dev_file.as_raw_fd(),
                DriverCmd::SetupTest as u64,
                DriverTestCase::TestInvalidEncFd,
            )
        };

        // Mock driver is guaranteed to return -1 in this test case
        assert_eq!(rc, -1);

        let eif_file = File::open(SAMPLE_EIF_PATH);
        if let Ok(eif_file) = eif_file {
            let result = EnclaveHandle::new(None, enc_mem, cpu_ids, eif_file, false);
            if let Err(err_str) = result {
                assert!(err_str.eq(ENC_HANDLE_INIT_FAULTY_DRIVER_ERR_STR));
            }
        } else {
            panic!(format!("Could not find EIF file: {}", SAMPLE_EIF_PATH));
        }
    }

    #[test]
    fn test_enclave_handle_init_good_driver() {
        let enc_mem = 32;
        let cpu_ids = vec![1, 3];
        let mem_info = procfs::Meminfo::new();

        assert!(mem_info.is_ok());
        let mem_info = mem_info.unwrap();

        let total_hugepages_available = mem_info.hugepages_total;

        if let Some(total_hugepages_available) = total_hugepages_available {
            let hugepagesize = get_hugepagesize();
            if enc_mem < total_hugepages_available * hugepagesize {
                let dev_file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("/dev/nitro_enclaves")
                    .ok_or_exit("Failed to open device file.");

                let _ = unsafe {
                    libc::ioctl(
                        dev_file.as_raw_fd(),
                        DriverCmd::SetupTest as u64,
                        DriverTestCase::TestValidEncFd,
                    )
                };

                let eif_file = File::open(SAMPLE_EIF_PATH);

                if let Ok(eif_file) = eif_file {
                    let handle_init_result =
                        EnclaveHandle::new(None, enc_mem, cpu_ids, eif_file, false);
                    assert!(handle_init_result.is_ok());
                } else {
                    panic!(format!("Could not find EIF file: {}", SAMPLE_EIF_PATH));
                }
            } else {
                panic!(format!(
                    "Not enough hugepages available. Minimum required number: {}",
                    (enc_mem << 20) / hugepagesize
                ));
            }
        }
    }

    #[test]
    fn test_enclave_handle_init_insufficient_memory() {
        let cpu_ids = vec![1, 3];
        let eif_file = File::open(SAMPLE_EIF_PATH);

        if let Ok(eif_file) = eif_file {
            let metadata = eif_file.metadata();

            if let Ok(metadata) = metadata {
                let enc_mem = (metadata.len() >> 20) / 2; // Half of EIF size

                let handle_init_result =
                    EnclaveHandle::new(None, enc_mem, cpu_ids, eif_file, false);
                assert!(handle_init_result.is_err());

                if let Err(err_str) = handle_init_result {
                    assert!(
                        err_str.starts_with("Requested memory is lower than the enclave image.")
                    );
                }
            }
        } else {
            panic!(format!("Could not find EIF file: {}", SAMPLE_EIF_PATH));
        }
    }

    #[test]
    fn test_init_memory_faulty_driver() {
        let enc_mem = 32;
        let cpu_ids = vec![1, 3];

        let dev_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/nitro_enclaves")
            .ok_or_exit("Failed to open device file.");

        let eif_file = File::open(SAMPLE_EIF_PATH);

        if let Ok(eif_file) = eif_file {
            let _ = unsafe {
                libc::ioctl(
                    dev_file.as_raw_fd(),
                    DriverCmd::SetupTest as u64,
                    DriverTestCase::TestValidEncFd,
                )
            };

            let enc_type: c_ulong = 0;
            let enc_fd =
                unsafe { libc::ioctl(dev_file.as_raw_fd(), KVM_CREATE_VM as _, &enc_type) };

            let mut enclave_handle = EnclaveHandle::default();
            enclave_handle.set_cpu_ids(cpu_ids);
            enclave_handle.set_cpu_fds(vec![]);
            enclave_handle.set_allocated_memory_mib(0);
            enclave_handle.set_slot_uid(0);
            enclave_handle.set_enclave_cid(None);
            enclave_handle.set_flags(0);
            enclave_handle.set_enc_fd(enc_fd);
            enclave_handle.set_resource_allocator(
                ResourceAllocator::new(enc_mem << 20)
                    .ok_or_exit("Failed to create resource allocator"),
            );
            enclave_handle.set_eif_file(Some(eif_file));

            let _ = unsafe {
                libc::ioctl(
                    dev_file.as_raw_fd(),
                    DriverCmd::SetupTest as u64,
                    DriverTestCase::TestInvalidMemReg,
                )
            };

            let regions = enclave_handle.get_resource_allocator().allocate();
            if let Ok(regions) = regions {
                let region = regions.get(0);

                if let Some(region) = region {
                    let kvm_mem_region = kvm_userspace_memory_region {
                        slot: 0,
                        flags: 0,
                        userspace_addr: *region.mem_addr(),
                        guest_phys_addr: 0,
                        memory_size: *region.mem_size(),
                    };
                    let _ = unsafe {
                        libc::ioctl(enc_fd, KVM_SET_USER_MEMORY_REGION as _, &kvm_mem_region)
                    };

                    assert_eq!(nix::errno::errno(), libc::EFAULT);
                }
            } else {
                panic!("Could not allocate memory regions");
            }
        } else {
            panic!(format!("Could not find EIF file: {}", SAMPLE_EIF_PATH));
        }
    }

    #[test]
    fn test_init_memory_good_driver() {
        let enc_mem = 32;
        let cpu_ids = vec![1, 3];

        let dev_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/nitro_enclaves")
            .ok_or_exit("Failed to open device file.");

        let eif_file = File::open(SAMPLE_EIF_PATH);

        if let Ok(eif_file) = eif_file {
            let _ = unsafe {
                libc::ioctl(
                    dev_file.as_raw_fd(),
                    DriverCmd::SetupTest as u64,
                    DriverTestCase::TestValidEncFd,
                )
            };

            let enc_type: c_ulong = 0;
            let enc_fd =
                unsafe { libc::ioctl(dev_file.as_raw_fd(), KVM_CREATE_VM as _, &enc_type) };

            let mut enclave_handle = EnclaveHandle::default();
            enclave_handle.set_cpu_ids(cpu_ids);
            enclave_handle.set_cpu_fds(vec![]);
            enclave_handle.set_allocated_memory_mib(0);
            enclave_handle.set_slot_uid(0);
            enclave_handle.set_enclave_cid(None);
            enclave_handle.set_flags(0);
            enclave_handle.set_enc_fd(enc_fd);
            enclave_handle.set_resource_allocator(
                ResourceAllocator::new(enc_mem << 20)
                    .ok_or_exit("Failed to create resource allocator"),
            );
            enclave_handle.set_eif_file(Some(eif_file));

            let _ = unsafe {
                libc::ioctl(
                    dev_file.as_raw_fd(),
                    DriverCmd::SetupTest as u64,
                    DriverTestCase::TestValidMemReg,
                )
            };

            let regions = enclave_handle.get_resource_allocator().allocate();
            if let Ok(regions) = regions {
                for region in regions {
                    let kvm_mem_region = kvm_userspace_memory_region {
                        slot: 0,
                        flags: 0,
                        userspace_addr: *region.mem_addr(),
                        guest_phys_addr: 0,
                        memory_size: *region.mem_size(),
                    };

                    let rc = unsafe {
                        libc::ioctl(enc_fd, KVM_SET_USER_MEMORY_REGION as _, &kvm_mem_region)
                    };

                    assert_eq!(rc, 0);
                }
            } else {
                panic!("Could not allocate memory regions");
            }
        } else {
            panic!(format!("Could not find EIF file: {}", SAMPLE_EIF_PATH));
        }
    }

    #[test]
    fn test_init_cpus_faulty_driver() {
        let enc_mem = 32;
        let cpu_ids = vec![1, 3];

        let dev_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/nitro_enclaves")
            .ok_or_exit("Failed to open device file.");

        let eif_file = File::open(SAMPLE_EIF_PATH);

        if let Ok(eif_file) = eif_file {
            let _ = unsafe {
                libc::ioctl(
                    dev_file.as_raw_fd(),
                    DriverCmd::SetupTest as u64,
                    DriverTestCase::TestValidEncFd,
                )
            };

            let enc_type: c_ulong = 0;
            let enc_fd =
                unsafe { libc::ioctl(dev_file.as_raw_fd(), KVM_CREATE_VM as _, &enc_type) };

            let mut enclave_handle = EnclaveHandle::default();
            enclave_handle.set_cpu_ids(cpu_ids);
            enclave_handle.set_cpu_fds(vec![]);
            enclave_handle.set_allocated_memory_mib(0);
            enclave_handle.set_slot_uid(0);
            enclave_handle.set_enclave_cid(None);
            enclave_handle.set_flags(0);
            enclave_handle.set_enc_fd(enc_fd);
            enclave_handle.set_resource_allocator(
                ResourceAllocator::new(enc_mem << 20)
                    .ok_or_exit("Failed to create resource allocator"),
            );
            enclave_handle.set_eif_file(Some(eif_file));

            let _ = unsafe {
                libc::ioctl(
                    dev_file.as_raw_fd(),
                    DriverCmd::SetupTest as u64,
                    DriverTestCase::TestInvalidVcpu,
                )
            };

            for cpu_id in enclave_handle.get_cpu_ids() {
                let _ = unsafe { libc::ioctl(enc_fd, KVM_CREATE_VCPU as _, cpu_id) };

                assert_eq!(nix::errno::errno(), libc::EINVAL);
            }
        } else {
            panic!(format!("Could not find EIF file: {}", SAMPLE_EIF_PATH));
        }
    }

    #[test]
    fn test_init_cpus_good_driver() {
        let enc_mem = 32;
        let cpu_ids = vec![1, 3];

        let dev_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/nitro_enclaves")
            .ok_or_exit("Failed to open device file.");

        let eif_file = File::open(SAMPLE_EIF_PATH);

        if let Ok(eif_file) = eif_file {
            let _ = unsafe {
                libc::ioctl(
                    dev_file.as_raw_fd(),
                    DriverCmd::SetupTest as u64,
                    DriverTestCase::TestValidEncFd,
                );
            };

            let enc_type: c_ulong = 0;
            let enc_fd =
                unsafe { libc::ioctl(dev_file.as_raw_fd(), KVM_CREATE_VM as _, &enc_type) };

            let mut enclave_handle = EnclaveHandle::default();
            enclave_handle.set_cpu_ids(cpu_ids);
            enclave_handle.set_cpu_fds(vec![]);
            enclave_handle.set_allocated_memory_mib(0);
            enclave_handle.set_slot_uid(0);
            enclave_handle.set_enclave_cid(None);
            enclave_handle.set_flags(0);
            enclave_handle.set_enc_fd(enc_fd);
            enclave_handle.set_resource_allocator(
                ResourceAllocator::new(enc_mem << 20)
                    .ok_or_exit("Failed to create resource allocator"),
            );
            enclave_handle.set_eif_file(Some(eif_file));

            let _ = unsafe {
                libc::ioctl(
                    dev_file.as_raw_fd(),
                    DriverCmd::SetupTest as u64,
                    DriverTestCase::TestValidVcpu,
                )
            };

            for cpu_id in enclave_handle.get_cpu_ids() {
                let rc = unsafe { libc::ioctl(enc_fd, KVM_CREATE_VCPU as _, cpu_id) };

                assert_eq!(rc, 0);
            }
        } else {
            panic!(format!("Could not find EIF file: {}", SAMPLE_EIF_PATH));
        }
    }

    #[test]
    fn test_enclave_handle_clear() {
        let enc_mem = 32;
        let cpu_ids = vec![1, 3];

        let dev_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/nitro_enclaves")
            .ok_or_exit("Failed to open device file.");

        let eif_file = File::open(SAMPLE_EIF_PATH);

        if let Ok(eif_file) = eif_file {
            let _ = unsafe {
                libc::ioctl(
                    dev_file.as_raw_fd(),
                    DriverCmd::SetupTest as u64,
                    DriverTestCase::TestValidEncFd,
                )
            };

            let enc_type: c_ulong = 0;
            let enc_fd =
                unsafe { libc::ioctl(dev_file.as_raw_fd(), KVM_CREATE_VM as _, &enc_type) };

            let mut enclave_handle = EnclaveHandle::default();
            enclave_handle.set_cpu_ids(cpu_ids);
            enclave_handle.set_cpu_fds(vec![]);
            enclave_handle.set_allocated_memory_mib(0);
            enclave_handle.set_slot_uid(0);
            enclave_handle.set_enclave_cid(None);
            enclave_handle.set_flags(0);
            enclave_handle.set_enc_fd(enc_fd);
            enclave_handle.set_resource_allocator(
                ResourceAllocator::new(enc_mem << 20)
                    .ok_or_exit("Failed to create resource allocator"),
            );
            enclave_handle.set_eif_file(Some(eif_file));

            enclave_handle.clear();

            assert_eq!(enclave_handle.get_cpu_fds().len(), 0);
            assert_eq!(enclave_handle.get_cpu_ids().len(), 0);
            assert_eq!(*enclave_handle.get_enclave_cid(), Some(0));
            assert_eq!(enclave_handle.get_slot_uid(), 0);
        } else {
            panic!(format!("Could not find EIF file: {}", SAMPLE_EIF_PATH));
        }
    }

    #[test]
    fn test_get_description_resources() {
        let enclave_cid = Some(18);
        let enc_mem = 32;
        let cpu_ids = vec![1, 3];
        let eif_file = File::open(SAMPLE_EIF_PATH);

        if let Ok(eif_file) = eif_file {
            let enclave_manager =
                EnclaveManager::new(enclave_cid, enc_mem, cpu_ids, eif_file, false);

            if let Ok(enclave_manager) = enclave_manager {
                let res = enclave_manager.get_description_resources();

                if let Ok(res) = res {
                    assert_eq!(res.0, 0); // slot_uid
                    assert_eq!(res.1, 18); // enclave_cid
                    assert_eq!(res.2, 2); // cpu_ids length
                    assert_eq!(res.3, 0); // allocated_memory_mib
                    assert_eq!(res.4, 0); // flags
                } else {
                    panic!("Failed to acquire handle");
                }
            }
        } else {
            panic!(format!("Could not find EIF file: {}", SAMPLE_EIF_PATH));
        }
    }
}
