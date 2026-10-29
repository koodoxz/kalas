//! XDP Program Loader

use aya::{
    include_bytes_aligned,
    maps::{HashMap, MapData, PerCpuArray, RingBuf},
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use anyhow::{Context, Result};
use std::path::Path;
use tracing::{info, warn};

pub struct XdpLoader {
    ebpf: Ebpf,
    interface: String,
}

impl XdpLoader {
    /// Load XDP program from bytes
    pub fn new(ebpf_bytes: &[u8], interface: &str) -> Result<Self> {
        let ebpf = Ebpf::load(ebpf_bytes).context("Failed to load eBPF program")?;
        
        Ok(Self {
            ebpf,
            interface: interface.to_string(),
        })
    }
    
    /// Load XDP program from file path
    pub fn from_file(path: &Path, interface: &str) -> Result<Self> {
        let bytes = std::fs::read(path).context("Failed to read eBPF object file")?;
        Self::new(&bytes, interface)
    }
    
    /// Attach XDP program to interface
    pub fn attach(&mut self, mode: XdpMode) -> Result<()> {
        let program: &mut Xdp = self.ebpf
            .program_mut("heimdall_xdp")
            .context("XDP program 'heimdall_xdp' not found")?
            .try_into()?;
        
        program.load()?;
        
        let flags = match mode {
            XdpMode::Skb => XdpFlags::SKB_MODE,
            XdpMode::Driver => XdpFlags::DRV_MODE,
            XdpMode::Hardware => XdpFlags::HW_MODE,
        };
        
        program.attach(&self.interface, flags)
            .context(format!("Failed to attach XDP to {}", self.interface))?;
        
        info!("✅ XDP attached to {} ({:?})", self.interface, mode);
        Ok(())
    }
    
    /// Get mutable reference to eBPF object
    pub fn ebpf_mut(&mut self) -> &mut Ebpf {
        &mut self.ebpf
    }
    
    /// Get reference to eBPF object
    pub fn ebpf(&self) -> &Ebpf {
        &self.ebpf
    }
    
    /// Chain a secondary XDP program for tail-call dispatch
    /// The secondary program will be loaded and inserted into JUMP_TABLE[index]
    pub fn chain_program(&mut self, secondary_path: &Path, index: u32) -> Result<()> {
        use aya::maps::ProgramArray;
        use aya::programs::Xdp;
        use std::os::fd::AsFd;
        
        // Load secondary eBPF object
        let secondary_bytes = std::fs::read(secondary_path)
            .context(format!("Failed to read secondary eBPF: {:?}", secondary_path))?;
        let mut secondary = Ebpf::load(&secondary_bytes)
            .context("Failed to load secondary eBPF")?;
        
        // Try to find and load XDP program with common names
        let program_name = if secondary.program_mut("mimir_xdp").is_some() {
            "mimir_xdp"
        } else if secondary.program_mut("xdp_prog").is_some() {
            "xdp_prog"
        } else if secondary.program_mut("xdp_main").is_some() {
            "xdp_main"
        } else {
            anyhow::bail!("No XDP program found in secondary eBPF");
        };
        
        // Now get the program and load it
        let prog = secondary.program_mut(program_name)
            .context("Program disappeared")?;
        let xdp: &mut Xdp = prog.try_into()?;
        xdp.load()?;
        
        info!("🔗 Loaded secondary XDP program: {}", program_name);
        
        // Get the FD and insert into JUMP_TABLE
        let fd = xdp.fd().context("Failed to get program FD")?;
        
        let mut jump_table: ProgramArray<_> = self.ebpf
            .take_map("JUMP_TABLE")
            .context("JUMP_TABLE map not found")?
            .try_into()?;
        
        jump_table.set(index, fd, 0)?;
        info!("🔗 Chained secondary program at JUMP_TABLE[{}]", index);
        
        // Keep secondary Ebpf alive (leak it for now)
        std::mem::forget(secondary);
        
        // CRITICAL FIX: Keep jump_table alive too!
        // Without this, the ProgramArray is dropped and the entry is lost
        std::mem::forget(jump_table);
        
        info!("✅ XDP chain established: HEIMDALL → {} (index {})", program_name, index);
        
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum XdpMode {
    Skb,       // Generic XDP (works everywhere)
    Driver,    // Native XDP (requires driver support)
    Hardware,  // Hardware offload (requires NIC support)
}

impl From<&str> for XdpMode {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "drv" | "driver" | "native" => XdpMode::Driver,
            "hw" | "hardware" | "offload" => XdpMode::Hardware,
            _ => XdpMode::Skb,
        }
    }
}
