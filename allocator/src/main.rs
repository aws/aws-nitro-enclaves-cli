use anyhow::{anyhow,Result};
mod resources;
mod error;
mod configuration;

fn main()  -> Result<()> {
	let _ = configuration::clear_everything_in_numa_node().map_err(|e| format!("Failed to clear previously allocated resources.{}",e));

	let pool = configuration::get_resource_pool_from_config()
        .map_err(|e| anyhow!("Failed to read config file: {}", e))?;

    let numa_node = resources::allocate_by_cpu_pools(pool.clone())
        .map_err(|e|
            anyhow!("Failed to allocate resources: {}", e))?;

    resources::allocate_by_cpu_count(pool, numa_node)
        .map_err(|e| {
            let _ = configuration::clear_everything_in_numa_node().map_err(|e| anyhow!("Failed to clear previously allocated resources.{}",e));
            anyhow!("Failed to allocate resources: {}", e)
        })?;

    Ok(())
}
