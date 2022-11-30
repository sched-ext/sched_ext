// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
#![deny(clippy::all)]
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use ::fb_procfs as procfs;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use bitvec::prelude::*;
use clap::Parser;

mod util;

oss_shim!();

/// Atropos is a multi-domain BPF / userspace hybrid scheduler where the BPF
/// part does simple round robin in each domain and the userspace part
/// calculates the load factor of each domain and tells the BPF part how to load
/// balance the domains.

/// This scheduler demonstrates dividing scheduling logic between BPF and
/// userspace and using rust to build the userspace part. An earlier variant of
/// this scheduler was used to balance across six domains, each representing a
/// chiplet in a six-chiplet AMD processor, and could match the performance of
/// production setup using CFS.
#[derive(Debug, Parser)]
struct Opt {
    /// Set the log level for more or less verbose output. --log_level=debug
    /// will output libbpf verbose details
    #[clap(short, long, default_value = "info")]
    log_level: String,
    /// Set the cpumask for a domain, provide multiple --cpumasks, one for each
    /// domain. E.g. --cpumasks 0xff_00ff --cpumasks 0xff00 will create two
    /// domains with the corresponding CPUs belonging to each domain. Each CPU
    /// must belong to precisely one domain.
    #[clap(short, long, required = true, min_values = 1)]
    cpumasks: Vec<String>,
    /// Switch all tasks to sched_ext. If not specified, only tasks which
    /// have their scheduling policy set to SCHED_EXT using
    /// sched_setscheduler(2) are switched.
    #[clap(short, long, default_value = "false")]
    all: bool,
    /// Enable load balancing. Periodically userspace will calculate the load
    /// factor of each domain and instruct BPF which processes to move.
    #[clap(short, long, default_value = "true")]
    load_balance: bool,
    /// Enable greedy task stealing. When a domain is idle, a cpu will attempt
    /// to steal tasks from a domain with at least greedy_threshold tasks
    /// enqueued. These tasks aren't permanently stolen from the domain.
    #[clap(short, long)]
    greedy_threshold: Option<u64>,
}

type CpusetDqPair = (Vec<BitVec<u64, Lsb0>>, Vec<i32>);

// Returns Vec of cpuset for each dq and a vec of dq for each cpu
fn parse_cpusets(cpumasks: &[String]) -> anyhow::Result<CpusetDqPair> {
    if cpumasks.len() > atropos_sys::MAX_DOMS as usize {
        bail!(
            "Number of requested DSQs ({}) is greater than MAX_DOMS ({})",
            cpumasks.len(),
            atropos_sys::MAX_DOMS
        );
    }
    let num_cpus = libbpf_rs::num_possible_cpus()?;
    if num_cpus > atropos_sys::MAX_CPUS as usize {
        bail!(
            "num_cpus ({}) is greater than MAX_CPUS ({})",
            num_cpus,
            atropos_sys::MAX_CPUS,
        );
    }
    let mut cpus = vec![-1i32; num_cpus];
    let mut cpusets = vec![bitvec![u64, Lsb0; 0; atropos_sys::MAX_CPUS as usize]; cpumasks.len()];
    for (dq, cpumask) in cpumasks.iter().enumerate() {
        let hex_str = {
            let mut tmp_str = cpumask
                .strip_prefix("0x")
                .unwrap_or(cpumask)
                .replace('_', "");
            if tmp_str.len() % 2 != 0 {
                tmp_str = "0".to_string() + &tmp_str;
            }
            tmp_str
        };
        let byte_vec = hex::decode(&hex_str)
            .with_context(|| format!("Failed to parse cpumask: {}", cpumask))?;

        for (index, &val) in byte_vec.iter().rev().enumerate() {
            let mut v = val;
            while v != 0 {
                let lsb = v.trailing_zeros() as usize;
                v &= !(1 << lsb);
                let cpu = index * 8 + lsb;
                if cpu > num_cpus {
                    bail!(
                        concat!(
                            "Found cpu ({}) in cpumask ({}) which is larger",
                            " than the number of cpus on the machine ({})"
                        ),
                        cpu,
                        cpumask,
                        num_cpus
                    );
                }
                if cpus[cpu] != -1 {
                    bail!(
                        "Found cpu ({}) with dq ({}) but also in cpumask ({})",
                        cpu,
                        cpus[cpu],
                        cpumask
                    );
                }
                cpus[cpu] = dq as i32;
                cpusets[dq].set(cpu, true);
            }
        }
        cpusets[dq].set_uninitialized(false);
    }

    for (cpu, &dq) in cpus.iter().enumerate() {
        if dq < 0 {
            bail!(
                "Cpu {} not assigned to any dq. Make sure it is covered by some --cpumasks argument.",
                cpu
            );
        }
    }

    Ok((cpusets, cpus))
}

struct Sample {
    total_cpu: procfs::CpuStat,
}

fn get_cpustats(reader: &mut procfs::ProcReader) -> anyhow::Result<Sample> {
    let stat = reader.read_stat().context("Failed to read procfs")?;
    Ok(Sample {
        total_cpu: stat
            .total_cpu
            .ok_or_else(|| anyhow!("Could not read total cpu stat in proc"))?,
    })
}

fn calculate_cpu_busy(prev: &procfs::CpuStat, next: &procfs::CpuStat) -> anyhow::Result<f64> {
    match (prev, next) {
        (
            procfs::CpuStat {
                user_usec: Some(prev_user),
                nice_usec: Some(prev_nice),
                system_usec: Some(prev_system),
                idle_usec: Some(prev_idle),
                iowait_usec: Some(prev_iowait),
                irq_usec: Some(prev_irq),
                softirq_usec: Some(prev_softirq),
                stolen_usec: Some(prev_stolen),
                guest_usec: _,
                guest_nice_usec: _,
            },
            procfs::CpuStat {
                user_usec: Some(curr_user),
                nice_usec: Some(curr_nice),
                system_usec: Some(curr_system),
                idle_usec: Some(curr_idle),
                iowait_usec: Some(curr_iowait),
                irq_usec: Some(curr_irq),
                softirq_usec: Some(curr_softirq),
                stolen_usec: Some(curr_stolen),
                guest_usec: _,
                guest_nice_usec: _,
            },
        ) => {
            let idle_usec = curr_idle - prev_idle;
            let iowait_usec = curr_iowait - prev_iowait;
            let user_usec = curr_user - prev_user;
            let system_usec = curr_system - prev_system;
            let nice_usec = curr_nice - prev_nice;
            let irq_usec = curr_irq - prev_irq;
            let softirq_usec = curr_softirq - prev_softirq;
            let stolen_usec = curr_stolen - prev_stolen;

            let busy_usec =
                user_usec + system_usec + nice_usec + irq_usec + softirq_usec + stolen_usec;
            let total_usec = idle_usec + busy_usec + iowait_usec;
            Ok(busy_usec as f64 / total_usec as f64)
        }
        _ => {
            bail!("Some procfs stats are not populated!");
        }
    }
}

fn calculate_pid_busy(
    prev: &procfs::PidStat,
    next: &procfs::PidStat,
    dur: std::time::Duration,
) -> anyhow::Result<f64> {
    match (
        (prev.user_usecs, prev.system_usecs),
        (next.user_usecs, prev.system_usecs),
    ) {
        ((Some(prev_user), Some(prev_system)), (Some(next_user), Some(next_system))) => {
            if (next_user >= prev_user) && (next_system >= prev_system) {
                let busy_usec = next_user + next_system - prev_user - prev_system;
                Ok(busy_usec as f64 / dur.as_micros() as f64)
            } else {
                bail!("Pid usage values look wrong");
            }
        }
        _ => {
            bail!("Some procfs stats are not populated!");
        }
    }
}

struct PidInfo {
    pub pid: i32,
    pub dom: u32,
    pub dom_mask: u64,
}

struct LoadInfo {
    pids_by_milliload: BTreeMap<u64, PidInfo>,
    pid_stats: BTreeMap<i32, procfs::PidStat>,
    global_load_sum: f64,
    dom_load: Vec<f64>,
}

// We calculate the load for each task and then each dom by enumerating all the
// tasks in task_data and calculating their CPU util from procfs.

// Given procfs reader, task data map, and pidstat from previous calculation,
// return:
//  * a sorted map from milliload -> pid_data,
//  * a map from pid -> pidstat
//  * a vec of per-dom looads
fn calculate_load(
    proc_reader: &procfs::ProcReader,
    task_data: &libbpf_rs::Map,
    interval: std::time::Duration,
    prev_pid_stat: &BTreeMap<i32, procfs::PidStat>,
    nr_doms: usize,
) -> anyhow::Result<LoadInfo> {
    let mut ret = LoadInfo {
        pids_by_milliload: BTreeMap::new(),
        pid_stats: BTreeMap::new(),
        global_load_sum: 0f64,
        dom_load: vec![0f64; nr_doms],
    };
    for key in task_data.keys() {
        if let Some(task_ctx_vec) = task_data
            .lookup(&key, libbpf_rs::MapFlags::ANY)
            .context("Failed to lookup task_data")?
        {
            let task_ctx =
                unsafe { &*(task_ctx_vec.as_slice().as_ptr() as *const atropos_sys::task_ctx) };
            let pid = i32::from_ne_bytes(
                key.as_slice()
                    .try_into()
                    .context("Invalid key length in task_data map")?,
            );
            match proc_reader.read_tid_stat(pid as u32) {
                Ok(stat) => {
                    ret.pid_stats.insert(pid, stat);
                }
                Err(procfs::Error::IoError(_, ref e))
                    if e.raw_os_error()
                        .map_or(false, |ec| ec == 2 || ec == 3 /* ENOENT or ESRCH */) =>
                {
                    continue;
                }
                Err(e) => {
                    bail!(e);
                }
            }
            let pid_load = match (prev_pid_stat.get(&pid), ret.pid_stats.get(&pid)) {
                (Some(prev_pid_stat), Some(next_pid_stat)) => {
                    calculate_pid_busy(prev_pid_stat, next_pid_stat, interval)?
                }
                // If we don't have any utilization #s for the process, just skip it
                _ => {
                    continue;
                }
            } * task_ctx.weight as f64;
            if !pid_load.is_finite() || pid_load <= 0.0 {
                continue;
            }
            ret.global_load_sum += pid_load;
            ret.dom_load[task_ctx.dom_id as usize] += pid_load;
            // Only record pids that are eligible for load balancing
            if task_ctx.dom_mask == (1u64 << task_ctx.dom_id) {
                continue;
            }
            ret.pids_by_milliload.insert(
                (pid_load * 1000.0) as u64,
                PidInfo {
                    pid,
                    dom: task_ctx.dom_id,
                    dom_mask: task_ctx.dom_mask,
                },
            );
        }
    }
    Ok(ret)
}

#[derive(Copy, Clone, Default)]
struct DomLoadBalanceInfo {
    load_to_pull: f64,
    load_to_give: f64,
}

#[derive(Default)]
struct LoadBalanceInfo {
    doms: Vec<DomLoadBalanceInfo>,
    doms_with_load_to_pull: BTreeMap<u32, f64>,
    doms_with_load_to_give: BTreeMap<u32, f64>,
}

// To balance dom loads we identify doms with lower and higher load than average
fn calculate_dom_load_balance(global_load_avg: f64, dom_load: &[f64]) -> LoadBalanceInfo {
    let mut ret = LoadBalanceInfo::default();
    ret.doms.resize(dom_load.len(), Default::default());

    const LOAD_IMBAL_HIGH_PCT: f64 = 0.10;
    const LOAD_IMBAL_MAX_ADJ_PCT: f64 = 0.10;
    let high = global_load_avg * LOAD_IMBAL_HIGH_PCT;
    let adj_max = global_load_avg * LOAD_IMBAL_MAX_ADJ_PCT;

    for (dom, dom_load) in dom_load.iter().enumerate() {
        let mut imbal = dom_load - global_load_avg;

        let mut dom_load_to_pull = 0f64;
        let mut dom_load_to_give = 0f64;
        if imbal >= 0f64 {
            dom_load_to_give = imbal;
        } else {
            imbal = -imbal;
            if imbal > high {
                dom_load_to_pull = f64::min(imbal, adj_max);
            }
        }
        ret.doms[dom].load_to_pull = dom_load_to_pull;
        ret.doms[dom].load_to_give = dom_load_to_give;
        if dom_load_to_pull > 0f64 {
            ret.doms_with_load_to_pull
                .insert(dom as u32, dom_load_to_pull);
        }
        if dom_load_to_give > 0f64 {
            ret.doms_with_load_to_give
                .insert(dom as u32, dom_load_to_give);
        }
    }
    ret
}

fn clear_map(map: &mut libbpf_rs::Map) {
    // XXX: libbpf_rs has some design flaw that make it impossible to
    // delete while iterating despite it being safe so we alias it here
    let deleter: &mut libbpf_rs::Map = unsafe { &mut *(map as *mut _) };
    for key in map.keys() {
        let _ = deleter.delete(&key);
    }
}

// Actually execute the load balancing. Concretely this writes pid -> dom
// entries into the lb_data map for bpf side to consume.
//
// The logic here is simple, greedily balance the heaviest load processes until
// either we have no doms with load to give or no doms with load to pull.
fn load_balance(
    global_load_avg: f64,
    lb_data: &mut libbpf_rs::Map,
    pids_by_milliload: &BTreeMap<u64, PidInfo>,
    mut doms_with_load_to_pull: BTreeMap<u32, f64>,
    mut doms_with_load_to_give: BTreeMap<u32, f64>,
) -> anyhow::Result<()> {
    clear_map(lb_data);
    const LOAD_IMBAL_MIN_ADJ_PCT: f64 = 0.01;
    let adj_min = global_load_avg * LOAD_IMBAL_MIN_ADJ_PCT;
    for (pid_milliload, pidinfo) in pids_by_milliload.iter().rev() {
        if doms_with_load_to_give.is_empty() || doms_with_load_to_pull.is_empty() {
            break;
        }

        let pid_load = *pid_milliload as f64 / 1000f64;
        let mut remove_to_give = None;
        let mut remove_to_pull = None;
        if let Some(dom_imbal) = doms_with_load_to_give.get_mut(&pidinfo.dom) {
            if *dom_imbal < pid_load {
                continue;
            }

            for (new_dom, new_dom_imbal) in doms_with_load_to_pull.iter_mut() {
                if (pidinfo.dom_mask & (1 << new_dom)) == 0 || *new_dom_imbal < pid_load {
                    continue;
                }

                *dom_imbal -= pid_load;
                if *dom_imbal <= adj_min {
                    remove_to_give = Some(pidinfo.dom);
                }
                *new_dom_imbal -= pid_load;
                if *new_dom_imbal <= adj_min {
                    remove_to_pull = Some(pidinfo.dom);
                }

                lb_data
                    .update(
                        &(pidinfo.pid as libc::pid_t).to_ne_bytes(),
                        &new_dom.to_ne_bytes(),
                        libbpf_rs::MapFlags::NO_EXIST,
                    )
                    .context("Failed to update lb_data")?;
                break;
            }
        }

        remove_to_give.map(|dom| doms_with_load_to_give.remove(&dom));
        remove_to_pull.map(|dom| doms_with_load_to_pull.remove(&dom));
    }
    Ok(())
}

fn print_stats(
    logger: slog::Logger,
    stats_map: &mut libbpf_rs::Map,
    nr_doms: usize,
    nr_cpus: usize,
    cpu_busy: f64,
    global_load_avg: f64,
    dom_load: &[f64],
    dom_lb_info: &[DomLoadBalanceInfo],
) -> anyhow::Result<()> {
    let stats = {
        let mut stats: Vec<u64> = Vec::new();
        let zero_vec = vec![vec![0u8; stats_map.value_size() as usize]; nr_cpus];
        for stat in 0..atropos_sys::stat_idx_ATROPOS_NR_STATS {
            let cpu_stat_vec = stats_map
                .lookup_percpu(&(stat as u32).to_ne_bytes(), libbpf_rs::MapFlags::ANY)
                .with_context(|| format!("Failed to lookup stat {}", stat))?
                .expect("per-cpu stat should exist");
            let sum = cpu_stat_vec
                .iter()
                .map(|val| {
                    u64::from_ne_bytes(
                        val.as_slice()
                            .try_into()
                            .expect("Invalid value length in stat map"),
                    )
                })
                .sum();
            stats_map
                .update_percpu(
                    &(stat as u32).to_ne_bytes(),
                    &zero_vec,
                    libbpf_rs::MapFlags::ANY,
                )
                .context("Failed to zero stat")?;
            stats.push(sum);
        }
        stats
    };
    let mut total = 0;
    total += stats[atropos_sys::stat_idx_ATROPOS_STAT_WAKE_SYNC as usize];
    total += stats[atropos_sys::stat_idx_ATROPOS_STAT_PREV_IDLE as usize];
    total += stats[atropos_sys::stat_idx_ATROPOS_STAT_PINNED as usize];
    total += stats[atropos_sys::stat_idx_ATROPOS_STAT_DIRECT_DISPATCH as usize];
    total += stats[atropos_sys::stat_idx_ATROPOS_STAT_DSQ_DISPATCH as usize];
    total += stats[atropos_sys::stat_idx_ATROPOS_STAT_GREEDY as usize];
    total += stats[atropos_sys::stat_idx_ATROPOS_STAT_LAST_TASK as usize];
    slog::info!(logger, "cpu={:5.1}", cpu_busy * 100.0);
    slog::info!(
        logger,
        "task_get_errs: {}, cpumask_errs: {}",
        stats[atropos_sys::stat_idx_ATROPOS_STAT_TASK_GET_ERR as usize],
        stats[atropos_sys::stat_idx_ATROPOS_STAT_CPUMASK_ERR as usize],
    );
    slog::info!(
        logger,
        "tot={:6} wake_sync={:4.1},prev_idle={:4.1},pinned={:4.1},direct={:4.1},dq={:4.1},greedy={:4.1}",
        total,
        stats[atropos_sys::stat_idx_ATROPOS_STAT_WAKE_SYNC as usize] as f64 / total as f64 * 100f64,
        stats[atropos_sys::stat_idx_ATROPOS_STAT_PREV_IDLE as usize] as f64 / total as f64 * 100f64,
        stats[atropos_sys::stat_idx_ATROPOS_STAT_PINNED as usize] as f64 / total as f64 * 100f64,
        stats[atropos_sys::stat_idx_ATROPOS_STAT_DIRECT_DISPATCH as usize] as f64 / total as f64
            * 100f64,
        stats[atropos_sys::stat_idx_ATROPOS_STAT_DSQ_DISPATCH as usize] as f64 / total as f64
            * 100f64,
        stats[atropos_sys::stat_idx_ATROPOS_STAT_GREEDY as usize] as f64 / total as f64 * 100f64,
    );

    slog::info!(
        logger,
        "load_avg:{:.1}, load_balances={}",
        global_load_avg,
        stats[atropos_sys::stat_idx_ATROPOS_STAT_LOAD_BALANCE as usize]
    );
    for i in 0..nr_doms {
        slog::info!(logger, "DOM[{:02}]", i);
        slog::info!(
            logger,
            " load={:.1} to_pull={:.1},to_give={:.1}",
            dom_load[i],
            dom_lb_info[i].load_to_pull,
            dom_lb_info[i].load_to_give,
        );
    }
    Ok(())
}

pub fn run(
    logger: slog::Logger,
    debug: bool,
    cpumasks: Vec<String>,
    switch_all: bool,
    balance_load: bool,
    greedy_threshold: Option<u64>,
) -> anyhow::Result<()> {
    slog::info!(logger, "Atropos Scheduler Initialized");
    let mut skel_builder = AtroposSkelBuilder::default();
    skel_builder.obj_builder.debug(debug);
    let mut skel = skel_builder.open().context("Failed to open BPF program")?;

    let (cpusets, cpus) = parse_cpusets(&cpumasks)?;
    let nr_doms = cpusets.len();
    let nr_cpus = libbpf_rs::num_possible_cpus()?;
    skel.rodata().nr_doms = nr_doms as u32;
    skel.rodata().nr_cpus = nr_cpus as u32;

    for (cpu, dom) in cpus.iter().enumerate() {
        skel.rodata().cpu_dom_id_map[cpu] = *dom as u32;
    }

    for (dom, cpuset) in cpusets.iter().enumerate() {
        let raw_cpuset_slice = cpuset.as_raw_slice();
        let dom_cpumask_slice = &mut skel.rodata().dom_cpumasks[dom];
        let (left, _) = dom_cpumask_slice.split_at_mut(raw_cpuset_slice.len());
        left.clone_from_slice(cpuset.as_raw_slice());
        slog::info!(logger, "dom {} cpumask {:X?}", dom, dom_cpumask_slice);
    }

    skel.rodata().switch_all = switch_all;

    if let Some(greedy) = greedy_threshold {
        skel.rodata().greedy_threshold = greedy;
    }

    let mut skel = skel.load().context("Failed to load BPF program")?;
    skel.attach().context("Failed to attach BPF program")?;

    let _structops = skel
        .maps_mut()
        .atropos()
        .attach_struct_ops()
        .context("Failed to attach atropos struct ops")?;
    slog::info!(logger, "Atropos Scheduler Attached");
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    let mut proc_reader = procfs::ProcReader::new();
    let mut prev_sample = get_cpustats(&mut proc_reader)?;
    let mut prev_pid_stat: BTreeMap<i32, procfs::PidStat> = BTreeMap::new();
    while !shutdown.load(Ordering::Relaxed)
        && unsafe { std::ptr::read_volatile(&skel.bss().exit_type as *const _) } == 0
    {
        let interval = std::time::Duration::from_secs(1);
        std::thread::sleep(interval);
        let now = std::time::SystemTime::now();
        let next_sample = get_cpustats(&mut proc_reader)?;
        let cpu_busy = calculate_cpu_busy(&prev_sample.total_cpu, &next_sample.total_cpu)?;
        prev_sample = next_sample;
        let load_info = calculate_load(
            &proc_reader,
            skel.maps().task_data(),
            interval,
            &prev_pid_stat,
            nr_doms,
        )?;
        prev_pid_stat = load_info.pid_stats;

        let global_load_avg = load_info.global_load_sum / nr_doms as f64;
        let mut lb_info = calculate_dom_load_balance(global_load_avg, &load_info.dom_load);

        let doms_with_load_to_pull = std::mem::take(&mut lb_info.doms_with_load_to_pull);
        let doms_with_load_to_give = std::mem::take(&mut lb_info.doms_with_load_to_give);
        if balance_load {
            load_balance(
                global_load_avg,
                skel.maps_mut().lb_data(),
                &load_info.pids_by_milliload,
                doms_with_load_to_pull,
                doms_with_load_to_give,
            )?;
            slog::info!(
                logger,
                "Load balancing took {:?}",
                now.elapsed().context("Getting a duration failed")?
            );
        }
        print_stats(
            logger.clone(),
            skel.maps_mut().stats(),
            nr_doms,
            nr_cpus,
            cpu_busy,
            global_load_avg,
            &load_info.dom_load,
            &lb_info.doms,
        )?;
    }
    /* Report msg if EXT_OPS_EXIT_ERROR */
    if skel.bss().exit_type == 2 {
        let exit_msg_cstr = unsafe { CStr::from_ptr(skel.bss().exit_msg.as_ptr() as *const _) };
        let exit_msg = exit_msg_cstr
            .to_str()
            .context("Failed to convert exit msg to string")?;
        eprintln!("exit_type={} msg={}", skel.bss().exit_type, exit_msg);
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let opts = Opt::parse();
    let logger = setup_logger(&opts.log_level)?;
    let debug = opts.log_level == "debug";

    run(
        logger,
        debug,
        opts.cpumasks,
        opts.all,
        opts.load_balance,
        opts.greedy_threshold,
    )
}
