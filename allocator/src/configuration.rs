use serde::Deserialize;
use crate::resources;
use crate::error::Error;

//deserializing from allocator.yaml file
#[derive(Debug, PartialEq, Deserialize,Clone)]
#[serde(deny_unknown_fields)]
#[serde(untagged)]
pub enum ResourcePool {
    CpuCount { memory_mib: usize , cpu_count: usize},
    CpuPool { cpu_pool: String, memory_mib: usize },
}
pub fn get_resource_pool_from_config()  -> Result<Vec<ResourcePool>, Box<dyn std::error::Error>> {
    //config file deserializing
    let f = std::fs::File::open("/etc/nitro_enclaves/allocator.yaml")?;
    let pool: Vec<ResourcePool> =  match serde_yaml::from_reader(f) {
        Ok(pool) => pool,
        Err(_) => {return Err(Box::new(Error::ConfigFileCorruption));},//error messages use anyhow
    };
    if pool.len() > 4 {
       eprintln!("{}",Error::MoreResourcePoolThanSupported);
    }
    Ok(pool)
}
pub fn get_current_allocated_cpu_pool() -> Result<Option<std::collections::BTreeSet::<usize>>, Box<dyn std::error::Error>> {
    let f = std::fs::read_to_string("/sys/module/nitro_enclaves/parameters/ne_cpus")?;
    if f.trim().is_empty() {
        return Ok(None);
    }
    let cpu_list = resources::cpu::parse_cpu_list(&f[..])?;
    Ok(Some(cpu_list))
}
//clears everything in a numa node.
pub fn clear_everything_in_numa_node() -> Result<(), Box<dyn std::error::Error>> {//change the name
    match get_current_allocated_cpu_pool()?{
		Some(cpu_list) => {
		//find numa by one of cpuids
		let numa = resources::cpu::get_numa_node_for_cpu(cpu_list.clone().into_iter().next().unwrap())?;
		//release everything
		let _ = resources::huge_pages::release_all_huge_pages(numa)?;
		let _ = resources::cpu::deallocate_cpu_set(&cpu_list);
		}
		None => {}  
  	};
    Ok(())
}

