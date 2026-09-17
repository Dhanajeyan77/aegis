use aya::Bpf;
use aya::programs::Lsm;
use aya::maps::RingBuf;
use std::convert::TryInto;
use tokio::signal;
use log::{info, warn, error};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    info!("Starting Aegis-BPF Rust Agent...");

    // In a real build, we compile the bpf.c to an ELF object and load it.
    // let mut bpf = Bpf::load(include_bytes_aligned!("../../bpf/aegis.bpf.o"))?;

    info!("Connecting to Go Control Plane at http://localhost:8080...");
    // reqwest::get("http://localhost:8080/register").await?;

    info!("Loading LSM hooks into the kernel...");
    /*
    let program: &mut Lsm = bpf.program_mut("aegis_bprm_check_security").unwrap().try_into()?;
    program.load()?;
    program.attach()?;
    */

    info!("Polling for eBPF events...");
    /*
    let mut ring_buf = RingBuf::try_from(bpf.map_mut("events").unwrap())?;
    // Poll loop goes here
    */

    info!("Agent running. Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
