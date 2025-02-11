mod resources;
mod error;
mod configuration;


fn main()  -> Result<(), Box<dyn std::error::Error>> {
	let _ = configuration::clear_everything_in_numa_node();

	match configuration::get_resource_pool_from_config() {
    	Ok(pool) => {			
			let numa_node = match resources::Allocation::allocate_by_cpu_pools(pool.clone()){
				Ok(numa) => numa,
				Err(e) =>{
					eprintln!("Allocation failed: {}",e);
					return Err(Box::new(e));
				},//proper error messages				
			};
      		match resources::Allocation::allocate_by_cpu_count(pool,numa_node) {
				Ok(_) => {},
				Err(e) => {
					let _ = configuration::clear_everything_in_numa_node();
					eprintln!(" Allocation failed: {}",e);
					return Err(Box::new(e));
				}
			} //check if allocation successful or not, if not clear what you allocated previously
    	}
    	Err(e) => {
			eprintln!("Allocation failed: {}",e);
      		return Err(e);
    	}

  	};
  	Ok(())
}
