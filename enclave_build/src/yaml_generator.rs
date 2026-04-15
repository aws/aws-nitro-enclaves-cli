// Copyright 2019-2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use tempfile::NamedTempFile;

/// Information about a kernel module for the bootstrap ramfs
#[derive(Debug, Clone)]
pub struct ModuleEntry {
    /// Module name (without .ko extension)
    pub name: String,
    /// Path to the .ko file on the host filesystem
    pub path: PathBuf,
    /// Dependencies (other module names)
    pub dependencies: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BootstrapRamfsTemplate {
    files: Vec<RamfsEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum RamfsEntry {
    Dir(DirTemplate),
    File(FileTemplate),
}

#[derive(Debug, Serialize, Deserialize)]
struct CustomerRamfsTemplate {
    prefix: String,
    init: Vec<String>,
    files: (
        DirTemplate,
        DirTemplate,
        DirTemplate,
        DirTemplate,
        DirTemplate,
        DirTemplate,
        FileTemplate,
        FileTemplate,
    ),
}

#[derive(Debug, Serialize, Deserialize)]
struct FileTemplate {
    path: String,
    source: String,
    mode: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DirTemplate {
    path: String,
    directory: bool,
    mode: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum YamlGeneratorError {
    TempfileError,
    ModuleOrderError(String),
}

pub struct YamlGenerator {
    docker_image: String,
    init_path: String,
    modules: Vec<ModuleEntry>,
    cmd_path: String,
    env_path: String,
}

impl YamlGenerator {
    pub fn new(
        docker_image: String,
        init_path: String,
        modules: Vec<ModuleEntry>,
        cmd_path: String,
        env_path: String,
    ) -> Self {
        YamlGenerator {
            docker_image,
            init_path,
            modules,
            cmd_path,
            env_path,
        }
    }

    /// Compute the topological sort of modules based on dependencies.
    /// Returns modules in load order (dependencies first, nsm.ko last).
    fn compute_module_load_order(&self) -> Result<Vec<&ModuleEntry>, YamlGeneratorError> {
        if self.modules.is_empty() {
            return Ok(vec![]);
        }

        // Build a map of module name -> module entry
        let module_map: HashMap<&str, &ModuleEntry> =
            self.modules.iter().map(|m| (m.name.as_str(), m)).collect();

        // Kahn's algorithm for topological sort
        // First, compute in-degrees (number of dependencies each module has within our set)
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();

        // Initialize all modules with in-degree 0
        for module in &self.modules {
            in_degree.insert(&module.name, 0);
            dependents.insert(&module.name, Vec::new());
        }

        // Count dependencies (only for modules we have)
        for module in &self.modules {
            for dep in &module.dependencies {
                if module_map.contains_key(dep.as_str()) {
                    // This module depends on 'dep', so increment this module's in-degree
                    *in_degree.get_mut(module.name.as_str()).unwrap() += 1;
                    // Add this module to dep's dependents list
                    dependents.get_mut(dep.as_str()).unwrap().push(&module.name);
                }
            }
        }

        // Start with modules that have no dependencies (in-degree 0), excluding nsm
        let mut queue: Vec<&str> = in_degree
            .iter()
            .filter(|(name, &degree)| degree == 0 && **name != "nsm")
            .map(|(name, _)| *name)
            .collect();

        // Sort for deterministic output
        queue.sort();

        let mut result: Vec<&ModuleEntry> = Vec::new();
        let mut nsm_module: Option<&ModuleEntry> = None;

        // Check if nsm exists and save it for later
        if let Some(nsm) = module_map.get("nsm") {
            nsm_module = Some(*nsm);
        }

        while let Some(module_name) = queue.pop() {
            let module = module_map.get(module_name).unwrap();

            result.push(module);

            // Reduce in-degree of dependents
            for dependent in dependents.get(module_name).unwrap() {
                let degree = in_degree.get_mut(dependent).unwrap();
                *degree -= 1;
                if *degree == 0 && *dependent != "nsm" {
                    queue.push(dependent);
                    queue.sort(); // Keep sorted for deterministic output
                }
            }
        }

        // Add nsm at the end if it exists
        if let Some(nsm) = nsm_module {
            // Check if all nsm dependencies (that are in our module set) have been processed
            let remaining_deps: usize = nsm
                .dependencies
                .iter()
                .filter(|dep| module_map.contains_key(dep.as_str()))
                .filter(|dep| !result.iter().any(|m| m.name == **dep))
                .count();

            if remaining_deps == 0 {
                result.push(nsm);
            } else {
                return Err(YamlGeneratorError::ModuleOrderError(
                    "Cannot satisfy nsm.ko dependencies".to_string(),
                ));
            }
        }

        // Check for cycles (if we didn't process all modules)
        if result.len() != self.modules.len() {
            return Err(YamlGeneratorError::ModuleOrderError(
                "Circular dependency detected in modules".to_string(),
            ));
        }

        Ok(result)
    }

    /// Generate the modules load order file content
    fn generate_modules_load_order(&self) -> Result<String, YamlGeneratorError> {
        let ordered_modules = self.compute_module_load_order()?;

        let mut content = String::from("# Module load order for Nitro Enclaves\n");
        content.push_str("# Load modules in this order (one per line)\n");

        for module in ordered_modules {
            content.push_str(&format!("{}.ko\n", module.name));
        }

        Ok(content)
    }

    pub fn get_bootstrap_ramfs(&self) -> Result<NamedTempFile, YamlGeneratorError> {
        // Generate the module load order file
        let load_order_content = self.generate_modules_load_order()?;
        let mut load_order_file =
            NamedTempFile::new().map_err(|_| YamlGeneratorError::TempfileError)?;
        load_order_file
            .write_all(load_order_content.as_bytes())
            .map_err(|_| YamlGeneratorError::TempfileError)?;

        // Build the files list
        let mut files: Vec<RamfsEntry> = Vec::new();

        // Add dev directory
        files.push(RamfsEntry::Dir(DirTemplate {
            path: String::from("dev"),
            directory: true,
            mode: String::from("0755"),
        }));

        // Add init
        files.push(RamfsEntry::File(FileTemplate {
            path: String::from("init"),
            source: self.init_path.clone(),
            mode: String::from("0755"),
        }));

        // Add modules load order file
        files.push(RamfsEntry::File(FileTemplate {
            path: String::from("modules_load_order"),
            source: load_order_file.path().to_str().unwrap().to_string(),
            mode: String::from("0644"),
        }));

        // Add all modules in load order
        let ordered_modules = self.compute_module_load_order()?;
        for module in ordered_modules {
            files.push(RamfsEntry::File(FileTemplate {
                path: format!("{}.ko", module.name),
                source: module.path.to_str().unwrap().to_string(),
                mode: String::from("0755"),
            }));
        }

        let ramfs = BootstrapRamfsTemplate { files };

        let yaml = serde_yaml::to_string(&ramfs);

        let mut file = NamedTempFile::new().map_err(|_| YamlGeneratorError::TempfileError)?;

        file.write_all(yaml.unwrap().as_bytes())
            .map_err(|_| YamlGeneratorError::TempfileError)?;

        // Keep the load_order_file alive by leaking it (it will be cleaned up when the process exits)
        // This is necessary because linuxkit needs to read the file
        std::mem::forget(load_order_file);

        Ok(file)
    }

    pub fn get_customer_ramfs(&self) -> Result<NamedTempFile, YamlGeneratorError> {
        let ramfs = CustomerRamfsTemplate {
            prefix: "rootfs/".to_string(),
            init: vec![self.docker_image.clone()],
            // Each directory must stay under rootfs, as expected by init
            files: (
                DirTemplate {
                    path: String::from("rootfs/dev"),
                    directory: true,
                    mode: String::from("0755"),
                },
                DirTemplate {
                    path: String::from("rootfs/run"),
                    directory: true,
                    mode: String::from("0755"),
                },
                DirTemplate {
                    path: String::from("rootfs/sys"),
                    directory: true,
                    mode: String::from("0755"),
                },
                DirTemplate {
                    path: String::from("rootfs/var"),
                    directory: true,
                    mode: String::from("0755"),
                },
                DirTemplate {
                    path: String::from("rootfs/proc"),
                    directory: true,
                    mode: String::from("0755"),
                },
                DirTemplate {
                    path: String::from("rootfs/tmp"),
                    directory: true,
                    mode: String::from("0755"),
                },
                FileTemplate {
                    path: String::from("cmd"),
                    source: self.cmd_path.clone(),
                    mode: String::from("0644"),
                },
                FileTemplate {
                    path: String::from("env"),
                    source: self.env_path.clone(),
                    mode: String::from("0644"),
                },
            ),
        };

        let yaml = serde_yaml::to_string(&ramfs);

        let mut file = NamedTempFile::new().map_err(|_| YamlGeneratorError::TempfileError)?;

        file.write_all(yaml.unwrap().as_bytes())
            .map_err(|_| YamlGeneratorError::TempfileError)?;

        Ok(file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;

    /// Test YAML config files are the same as the ones written by hand
    #[test]
    fn test_ramfs_single_module() {
        let modules = vec![ModuleEntry {
            name: String::from("nsm"),
            path: PathBuf::from("path_to_nsm"),
            dependencies: vec![],
        }];

        let yaml_generator = YamlGenerator::new(
            String::from("docker_image"),
            String::from("path_to_init"),
            modules,
            String::from("path_to_cmd"),
            String::from("path_to_env"),
        );

        let bootstrap_ramfs = yaml_generator.get_bootstrap_ramfs().unwrap();
        let mut bootstrap_data = String::new();
        let mut bootstrap_file = File::open(bootstrap_ramfs.path()).unwrap();
        bootstrap_file.read_to_string(&mut bootstrap_data).unwrap();

        // Check that the YAML contains expected entries
        assert!(bootstrap_data.contains("path: dev"));
        assert!(bootstrap_data.contains("path: init"));
        assert!(bootstrap_data.contains("path: modules_load_order"));
        assert!(bootstrap_data.contains("path: nsm.ko"));
    }

    #[test]
    fn test_ramfs_multiple_modules_with_deps() {
        // Create modules with dependencies:
        // nsm depends on virtio, virtio_ring
        // virtio depends on virtio_ring
        // virtio_ring has no deps
        let modules = vec![
            ModuleEntry {
                name: String::from("nsm"),
                path: PathBuf::from("path_to_nsm"),
                dependencies: vec![String::from("virtio"), String::from("virtio_ring")],
            },
            ModuleEntry {
                name: String::from("virtio"),
                path: PathBuf::from("path_to_virtio"),
                dependencies: vec![String::from("virtio_ring")],
            },
            ModuleEntry {
                name: String::from("virtio_ring"),
                path: PathBuf::from("path_to_virtio_ring"),
                dependencies: vec![],
            },
        ];

        let yaml_generator = YamlGenerator::new(
            String::from("docker_image"),
            String::from("path_to_init"),
            modules,
            String::from("path_to_cmd"),
            String::from("path_to_env"),
        );

        // Test load order computation
        let load_order = yaml_generator.compute_module_load_order().unwrap();
        let names: Vec<&str> = load_order.iter().map(|m| m.name.as_str()).collect();

        // virtio_ring must come before virtio (virtio depends on it)
        // virtio must come before nsm (nsm depends on it)
        // nsm must be last
        assert_eq!(names.last(), Some(&"nsm"));

        let virtio_ring_pos = names.iter().position(|&n| n == "virtio_ring").unwrap();
        let virtio_pos = names.iter().position(|&n| n == "virtio").unwrap();
        let nsm_pos = names.iter().position(|&n| n == "nsm").unwrap();

        assert!(virtio_ring_pos < virtio_pos);
        assert!(virtio_pos < nsm_pos);
    }

    #[test]
    fn test_customer_ramfs() {
        let modules = vec![ModuleEntry {
            name: String::from("nsm"),
            path: PathBuf::from("path_to_nsm"),
            dependencies: vec![],
        }];

        let yaml_generator = YamlGenerator::new(
            String::from("docker_image"),
            String::from("path_to_init"),
            modules,
            String::from("path_to_cmd"),
            String::from("path_to_env"),
        );

        let mut customer_data = String::new();
        let customer_ramfs = yaml_generator.get_customer_ramfs().unwrap();
        let mut customer_ramfs = File::open(customer_ramfs.path()).unwrap();
        customer_ramfs.read_to_string(&mut customer_data).unwrap();
        assert_eq!(
            customer_data,
            "---\
             \nprefix: rootfs/\
             \ninit:\
             \n  - docker_image\
             \nfiles:\
             \n  - path: rootfs/dev\
             \n    directory: true\
             \n    mode: \"0755\"\
             \n  - path: rootfs/run\
             \n    directory: true\
             \n    mode: \"0755\"\
             \n  - path: rootfs/sys\
             \n    directory: true\
             \n    mode: \"0755\"\
             \n  - path: rootfs/var\
             \n    directory: true\
             \n    mode: \"0755\"\
             \n  - path: rootfs/proc\
             \n    directory: true\
             \n    mode: \"0755\"\
             \n  - path: rootfs/tmp\
             \n    directory: true\
             \n    mode: \"0755\"\
             \n  - path: cmd\
             \n    source: path_to_cmd\
             \n    mode: \"0644\"\
             \n  - path: env\
             \n    source: path_to_env\
             \n    mode: \"0644\"\
             \n\
             "
        );
    }
}
