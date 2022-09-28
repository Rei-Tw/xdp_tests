use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{thread, time};

use anyhow::{bail, Result};
use structopt::StructOpt;

use std::mem;

#[path = "bpf/.output/xdptests.skel.rs"]
mod xdptests;
use xdptests::*;

use libbpf_rs::{Map, MapType, MapFlags};
use libbpf_rs::libbpf_sys::bpf_map_create_opts;


#[derive(Debug, StructOpt)]
struct Command {
    #[structopt(default_value = "0")]
    ifindex: i32,
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn load_dummy_map_fd(open_skel: &mut OpenXdptestsSkel) -> Result<()> {
    let bpf_opts = bpf_map_create_opts {
        sz: mem::size_of::<bpf_map_create_opts>() as u64,
        ..bpf_map_create_opts::default()
    };

    let dummy: Map = Map::create(MapType::Hash,
        Some("hm_dummy"),
        4,
        4,
        86400,
        &bpf_opts
    ).expect("Map is invalid.");
    open_skel.maps_mut().hmm_prots().set_inner_map_fd(&dummy);
    Ok(())
}

fn add_map(skel: &mut XdptestsSkel, proto: u32) -> Result<()> {
    let key = proto.to_ne_bytes();
    let bpf_opts = bpf_map_create_opts {
        sz: mem::size_of::<bpf_map_create_opts>() as u64,
        ..bpf_map_create_opts::default()
    };
    let map = Map::create(
        MapType::Hash,
        Some("hm_test"),
        4,
        4,
        86400,
        &bpf_opts 
    )?;

    let map_fd = map.fd().to_ne_bytes();

    skel.maps_mut().hmm_prots().update(&key, &map_fd, MapFlags::NO_EXIST)?;

    Ok(())
}

fn main() -> Result<()> {
    let opts = Command::from_args();

    if opts.ifindex == 0 {
        panic!("Invalid interface index. You can find the index by using the command : ip a");
    }

    bump_memlock_rlimit()?;

    let mut skel_builder = XdptestsSkelBuilder::default();
    skel_builder.obj_builder.debug(true);
    let mut open_skel = skel_builder.open()?;
    load_dummy_map_fd(&mut open_skel)?;
    
    let mut skel = open_skel.load()?;
    let link = skel.progs_mut().xdptests().attach_xdp(opts.ifindex)?;

    skel.links = XdptestsLinks {
        xdptests: Some(link),
    };
    
    add_map(&mut skel, 0x11)?;

    // temporary loop
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        eprint!(".");
        thread::sleep(time::Duration::from_secs(1));
    }

    Ok(())
}
