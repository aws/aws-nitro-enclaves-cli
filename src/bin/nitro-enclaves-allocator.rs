// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reserves the CPUs and hugepage memory configured in allocator.yaml for Nitro
//! Enclaves. Started by nitro-enclaves-allocator.service.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::process::exit;

type Result<T> = std::result::Result<T, String>;
/// Sets `nr_hugepages` of the i-th hugepage size when given a count, then reads it back.
type Pages<'a> = &'a mut dyn FnMut(usize, Option<i128>) -> io::Result<i128>;

const POOL_FILE: &str = "module/nitro_enclaves/parameters/ne_cpus";
const CPU_DIR: &str = "devices/system/cpu";
/// `ne_cpus` is a 512-byte buffer that also holds the newline and the NUL.
const MAX_POOL_LEN: usize = 510;
/// Far above any kernel's CPU limit; keeps a bogus range from filling memory.
const MAX_CPU: u32 = 65535;
const EPERM: i32 = 1;

const ERR_NO_POOL_FILE: &str =
    "The CPU pool file is missing. Please make sure the Nitro Enclaves driver is inserted.";
const ERR_NO_CPUS: &str =
    "Failed to find suitable CPUs for the Nitro Enclaves CPU pool after checking all NUMA nodes.";
const ERR_EMPTY_CPU_POOL: &str = "No CPUs are off-line. Please configure the CPU pool first.";
const ERR_MISSING_NODE: &str =
    "Failed to find NUMA node for a CPU. This indicates an invalid SysFS configuration.";
const ERR_INVALID_NODE: &str = "Invalid NUMA node for a CPU. This indicates an invalid CPU ID.";
const ERR_CLEAR_PAGE: &str = "Failed to clear huge page(s). Some pages may be in use.";
const ERR_SET_PAGE: &str =
    "Failed to set a number of huge pages. This may indicate insufficient system resources.";
const ERR_ROLLBACK_PAGE: &str =
    "Failed to roll back a number of huge pages. Some pages may be in use.";
const ERR_INSUFFICIENT_MEMORY: &str = "Failed to configure entire amount of requested memory. \
     This indicates insufficient system resources.";

fn main() {
    let mut config = std::env::var_os("NITRO_CLI_INSTALL_DIR").unwrap_or_default();
    config.push("/etc/nitro_enclaves/allocator.yaml");
    if let Err(e) = run(Path::new("/sys"), Path::new(&config)) {
        eprintln!("Error: {e}");
        exit(1);
    }
}

fn run(sys: &Path, config: &Path) -> Result<()> {
    let text = fs::read(config).map_err(|e| format!("Failed to read {}: {e}", config.display()))?;
    let cfg = parse_config(config, &String::from_utf8_lossy(&text))?;
    let bytes = memory_bytes(&cfg.memory_mib)?;
    let pool = match cfg.cpu_pool.as_str() {
        "" => None,
        p => {
            // The kernel reads `N` as the last possible CPU.
            let possible = read_cpus(&sys.join(CPU_DIR).join("possible"));
            let last = possible.and_then(|c| c.last().copied()).unwrap_or(MAX_CPU);
            let cpus = parse_cpus(p, last);
            Some(cpus.ok_or_else(|| format!("The CPU pool value ({p}) is invalid."))?)
        }
    };

    // Bring the old pool back online. The driver then rejects the empty pool with EINVAL.
    if let Err(e) = write(&sys.join(POOL_FILE), "") {
        if e.raw_os_error() == Some(EPERM) {
            return Err(
                "Could not re-online CPUs because there is at least one enclave \
                currently running. Make sure you stop all enclaves prior to re-starting the \
                nitro-enclaves-allocator.service."
                    .into(),
            );
        }
    }

    let cpus = if let Some(cpus) = pool {
        configure_cpu_pool(sys, &cpus)?;
        configure_huge_pages(sys, &cpus, bytes)?;
        format!("CPU pool: {}", cfg.cpu_pool)
    } else {
        if !sys.join(POOL_FILE).is_file() {
            return Err(ERR_NO_POOL_FILE.into());
        }
        println!("Auto-generating the enclave CPU pool by using the CPU count...");
        let mut cpus = Topology::read(sys)?.select(&cfg.cpu_count, &mut |node, cpus| {
            println!(
                "Will try to reserve {} MB of memory on node {node}.",
                cfg.memory_mib
            );
            configure_huge_pages(sys, cpus, bytes)
        })?;
        cpus.sort_unstable();
        println!(
            "Auto-generated the enclave CPU pool: {}.",
            format_cpus(&cpus)
        );
        configure_cpu_pool(sys, &cpus)?;
        format!("{} CPUs", cfg.cpu_count)
    };
    println!(
        "Successfully allocated Nitro Enclaves resources: {} MiB, {cpus}",
        cfg.memory_mib
    );
    Ok(())
}

#[derive(Debug, Default, PartialEq)]
struct Config {
    memory_mib: String,
    cpu_count: String,
    cpu_pool: String,
}

/// Parses allocator.yaml with the rules of the shell script it replaces: `key: value`
/// lines after a `---` line, each read like bash `read` and cut up like its `sed`.
fn parse_config(path: &Path, text: &str) -> Result<Config> {
    let mut cfg = Config::default();
    let mut started = false;
    for (i, line) in read_lines(text).iter().enumerate() {
        if line.trim_start_matches(is_space).starts_with('#') {
            continue;
        }
        if line == "---" {
            started = true;
            continue;
        }
        if !started {
            continue;
        }
        let key: String = line
            .split(':')
            .next()
            .unwrap_or_default()
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        let slot = match key.as_str() {
            "memory_mib" => &mut cfg.memory_mib,
            "cpu_count" => &mut cfg.cpu_count,
            "cpu_pool" => &mut cfg.cpu_pool,
            _ => {
                let at = format!("{}:{}", path.display(), i + 1);
                return Err(format!("Error in {at} - unexpected: {key}"));
            }
        };
        *slot = config_value(line);
        if slot.is_empty() {
            let at = format!("{}:{}", path.display(), i + 1);
            return Err(format!("Error in {at} - missing value for {key}"));
        }
    }
    if cfg.memory_mib.is_empty() {
        return Err("Config error: missing memory reservation (`memory_mib`).".into());
    }
    match (cfg.cpu_count.is_empty(), cfg.cpu_pool.is_empty()) {
        (true, true) => {
            Err("Config error: missing CPU reservation (either `cpu_count` or `cpu_pool`).".into())
        }
        (false, false) => Err("Config error: `cpu_count` conflicts with `cpu_pool`.".into()),
        _ => Ok(cfg),
    }
}

/// Splits `text` the way `while read line` does: `\x` becomes `x`, a backslash
/// before a newline joins two lines, spaces and tabs around a line are dropped,
/// and a last line without a newline is ignored.
fn read_lines(text: &str) -> Vec<String> {
    let (mut lines, mut line, mut escaped) = (Vec::new(), String::new(), false);
    for c in text.chars() {
        match c {
            '\\' if !escaped => escaped = true,
            '\n' if escaped => escaped = false,
            '\n' => {
                lines.push(line.trim_matches(|c| c == ' ' || c == '\t').to_string());
                line.clear();
            }
            _ => {
                line.push(c);
                escaped = false;
            }
        }
    }
    lines
}

/// The value as the script's `sed` cut it out: drop everything through the last `:`
/// that has a character before it, then the first run of whitespace with one `"`
/// right after it, then one trailing `"`.
fn config_value(line: &str) -> String {
    let value = match line.rfind(':') {
        Some(i) if i > 0 => &line[i + 1..],
        _ => line,
    };
    let value = match value.find(is_space) {
        Some(i) => {
            let rest = value[i..].trim_start_matches(is_space);
            value[..i].to_string() + rest.strip_prefix('"').unwrap_or(rest)
        }
        None => value.to_string(),
    };
    match value.strip_suffix('"') {
        Some(stripped) => stripped.to_string(),
        None => value,
    }
}

/// Whitespace as `\s` matches it in grep and sed (lines hold no newline).
fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\x0b' | '\x0c' | '\r')
}

fn is_number(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// memory_mib in bytes. Like the shell arithmetic it replaces, a leading 0 means octal.
fn memory_bytes(mib: &str) -> Result<i128> {
    let radix = if mib.len() > 1 && mib.starts_with('0') {
        8
    } else {
        10
    };
    is_number(mib)
        .then(|| i64::from_str_radix(mib, radix).ok()?.checked_mul(1 << 20))
        .flatten()
        .map(i128::from)
        .ok_or_else(|| format!("The needed memory amount ({mib}) is invalid."))
}

/// Parses CPUs and ranges separated by commas or whitespace, as the kernel's
/// cpulist_parse() does, with `N` standing for `last`. Returns the CPUs sorted,
/// without duplicates.
fn parse_cpus(list: &str, last: u32) -> Option<Vec<u32>> {
    let num = |s: &str| -> Option<u32> {
        let n = if s == "N" {
            last
        } else {
            s.parse().ok().filter(|_| is_number(s))?
        };
        (n <= MAX_CPU).then_some(n)
    };
    let mut cpus = BTreeSet::new();
    for item in list
        .split(|c: char| c == ',' || c == '\n' || is_space(c))
        .filter(|s| !s.is_empty())
    {
        let (first, last) = item.split_once('-').unwrap_or((item, item));
        let (first, last) = (num(first)?, num(last)?);
        if first > last {
            return None;
        }
        cpus.extend(first..=last);
    }
    (!cpus.is_empty()).then(|| cpus.into_iter().collect())
}

/// Formats sorted CPUs as ranges, e.g. `1-3,5`.
fn format_cpus(cpus: &[u32]) -> String {
    let mut ranges: Vec<(u32, u32)> = Vec::new();
    for &cpu in cpus {
        match ranges.last_mut() {
            Some((_, last)) if *last + 1 == cpu => *last = cpu,
            _ => ranges.push((cpu, cpu)),
        }
    }
    let ranges: Vec<String> = ranges
        .iter()
        .map(|&(a, b)| {
            if a == b {
                a.to_string()
            } else {
                format!("{a}-{b}")
            }
        })
        .collect();
    ranges.join(",")
}

fn read_cpus(path: &Path) -> Option<Vec<u32>> {
    parse_cpus(&fs::read_to_string(path).ok()?, MAX_CPU)
}

/// Writes `value` and a newline in one write(2), like `echo value > path`, but never
/// creates `path`.
fn write(path: &Path, value: &str) -> io::Result<()> {
    OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)?
        .write_all(format!("{value}\n").as_bytes())
}

/// The NUMA node of a CPU, from its `nodeN` link in sysfs.
fn cpu_node(sys: &Path, cpu: u32) -> Option<u32> {
    fs::read_dir(sys.join(format!("{CPU_DIR}/cpu{cpu}")))
        .ok()?
        .filter_map(|e| {
            e.ok()?
                .file_name()
                .to_str()?
                .strip_prefix("node")?
                .parse()
                .ok()
        })
        .next()
}

/// Hands the CPUs to the driver, which takes them offline.
fn configure_cpu_pool(sys: &Path, cpus: &[u32]) -> Result<()> {
    let file = sys.join(POOL_FILE);
    if !file.is_file() {
        return Err(ERR_NO_POOL_FILE.into());
    }
    println!("Configuring the enclave CPU pool...");
    let list = format_cpus(cpus);
    if list.len() > MAX_POOL_LEN {
        let len = list.len();
        return Err(format!(
            "The CPU pool needs {len} characters, but the driver accepts at most {MAX_POOL_LEN}."
        ));
    }
    write(&file, &list).map_err(|_| "Failed to configure the CPU pool.")?;
    println!("Done.");
    Ok(())
}

/// Reserves `bytes` of hugepages on the NUMA node of `cpus`.
fn configure_huge_pages(sys: &Path, cpus: &[u32], bytes: i128) -> Result<()> {
    println!("Configuring the huge page memory...");
    let mut node = None;
    for &cpu in cpus {
        let n = cpu_node(sys, cpu).ok_or(ERR_MISSING_NODE)?;
        if *node.get_or_insert(n) != n {
            return Err(ERR_INVALID_NODE.into());
        }
    }
    let node = node.ok_or(ERR_EMPTY_CPU_POOL)?;
    let dir = sys.join(format!("devices/system/node/node{node}/hugepages"));
    let mut sizes: Vec<(String, i128)> = fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .filter_map(|e| {
            let name = e.ok()?.file_name().into_string().ok()?;
            let key = name.strip_prefix("hugepages-")?.to_string();
            let kib: i128 = key.strip_suffix("kB")?.parse().ok()?;
            (kib > 0).then_some((key, kib << 10))
        })
        .collect();
    sizes.sort_by_key(|s| std::cmp::Reverse(s.1));
    let files: Vec<_> = sizes
        .iter()
        .map(|(key, _)| dir.join(format!("hugepages-{key}/nr_hugepages")))
        .collect();
    reserve(&sizes, bytes, &mut |i, count| {
        if let Some(count) = count {
            write(&files[i], &count.to_string())?;
        }
        let text = fs::read_to_string(&files[i])?;
        text.trim()
            .parse()
            .map_err(|_| io::ErrorKind::InvalidData.into())
    })?;
    println!("Done.");
    Ok(())
}

/// Splits `bytes`, rounded up to the smallest page size, over the hugepage `sizes`
/// (largest first, as many pages of each as fit) and restores the previous
/// reservation if the kernel grants too few pages.
fn reserve(sizes: &[(String, i128)], bytes: i128, pages: Pages) -> Result<()> {
    let smallest = sizes.last().ok_or(ERR_INSUFFICIENT_MEMORY)?.1;
    let mut left = (1 + (bytes - 1) / smallest) * smallest;
    let mut saved = Vec::new();
    for i in 0..sizes.len() {
        saved.push(pages(i, None).map_err(|_| ERR_SET_PAGE)?);
    }
    clear(sizes.len(), pages)?;
    for (i, (key, size)) in sizes.iter().enumerate() {
        let granted = pages(i, Some(left / size)).map_err(|_| ERR_SET_PAGE)?;
        if granted != 0 {
            println!("- Reserved {granted} pages of type: {key}.");
        }
        left -= size * granted;
        if left == 0 {
            return Ok(());
        }
    }
    println!("Memory configuration failed, rolling back memory reservations...");
    clear(sizes.len(), pages)?;
    for (i, &count) in saved.iter().enumerate() {
        pages(i, Some(count)).map_err(|_| ERR_SET_PAGE)?;
    }
    for (i, &count) in saved.iter().enumerate() {
        if pages(i, None).ok() != Some(count) {
            return Err(ERR_ROLLBACK_PAGE.into());
        }
    }
    Err(ERR_INSUFFICIENT_MEMORY.into())
}

fn clear(sizes: usize, pages: Pages) -> Result<()> {
    (0..sizes)
        .try_for_each(|i| pages(i, Some(0)).map(drop))
        .map_err(|_| ERR_CLEAR_PAGE.into())
}

struct Cpu {
    id: u32,
    node: Option<u32>,
    siblings: Vec<u32>,
}

/// The online CPUs, as the shell script saw them through lscpu.
struct Topology {
    present: usize,
    threads_per_core: usize,
    cpu0_node: u32,
    cpus: Vec<Cpu>,
}

impl Topology {
    fn read(sys: &Path) -> Result<Self> {
        let dir = sys.join(CPU_DIR);
        let list =
            |name: &str| read_cpus(&dir.join(name)).ok_or("Failed to get the number of CPUs.");
        let present = list("present")?.len();
        let cpus = list("online")?
            .into_iter()
            .map(|id| {
                let siblings =
                    read_cpus(&dir.join(format!("cpu{id}/topology/thread_siblings_list")))
                        .ok_or_else(|| format!("Failed to get the core id for CPU {id}."))?;
                Ok(Cpu {
                    id,
                    node: cpu_node(sys, id),
                    siblings,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Topology::new(present, cpus)
    }

    fn new(present: usize, cpus: Vec<Cpu>) -> Result<Self> {
        let cpu0_node = cpus
            .iter()
            .find(|c| c.id == 0)
            .and_then(|c| c.node)
            .ok_or("Failed to get the NUMA node of CPU 0.")?;
        let threads_per_core = cpus.iter().map(|c| c.siblings.len()).max().unwrap_or(1);
        Ok(Topology {
            present,
            threads_per_core,
            cpu0_node,
            cpus,
        })
    }

    /// Picks `count` CPUs that form whole cores on one NUMA node, keeping CPU 0 and
    /// its siblings for the parent VM. The node is used only if `reserve(node, cpus)`,
    /// which reserves the memory there, succeeds.
    fn select(
        &self,
        count: &str,
        reserve: &mut dyn FnMut(u32, &[u32]) -> Result<()>,
    ) -> Result<Vec<u32>> {
        let threads = self.threads_per_core;
        if !is_number(count) {
            return Err(format!("The CPU count value ({count}) is invalid."));
        }
        // Like test(1), treat counts that overflow 64 bits as not higher than 0.
        let count = count
            .parse::<i64>()
            .ok()
            .filter(|&n| n > 0)
            .ok_or("Provided CPU count is not higher than 0.")? as usize;
        if count > self.present {
            let present = self.present;
            return Err(format!(
                "Provided CPU count is higher than available CPUs - {present}."
            ));
        }
        if !count.is_multiple_of(threads) {
            return Err(format!(
                "The CPU count is not multiple of {threads} (threads per core)."
            ));
        }
        let nodes: BTreeSet<u32> = self.cpus.iter().filter_map(|c| c.node).collect();
        let mut error = None;
        for node in nodes {
            error = None;
            let cpus: Vec<&Cpu> = self.cpus.iter().filter(|c| c.node == Some(node)).collect();
            let kept = if node == self.cpu0_node { threads } else { 0 };
            if cpus.len() < count + kept {
                continue;
            }
            let mut pool = Vec::new();
            for cpu in cpus.iter().filter(|c| c.id != 0) {
                let core: Vec<u32> = cpu.siblings.iter().copied().filter(|&c| c != 0).collect();
                if core.len() != threads {
                    continue;
                }
                for c in core {
                    if !pool.contains(&c) {
                        pool.push(c);
                    }
                }
                if pool.len() == count {
                    match reserve(node, &pool) {
                        Ok(()) => return Ok(pool),
                        Err(e) => {
                            error = Some(e);
                            break;
                        }
                    }
                }
            }
        }
        Err(error.unwrap_or_else(|| ERR_NO_CPUS.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Config> {
        parse_config(Path::new("a.yaml"), text)
    }

    fn config(memory_mib: &str, cpu_count: &str, cpu_pool: &str) -> Result<Config> {
        Ok(Config {
            memory_mib: memory_mib.into(),
            cpu_count: cpu_count.into(),
            cpu_pool: cpu_pool.into(),
        })
    }

    #[test]
    fn config_follows_the_shell_parser() {
        assert_eq!(
            parse(include_str!("../../bootstrap/allocator.yaml")),
            config("512", "2", "")
        );
        // Text before `---`, quotes, the last colon, a CR that follows a value directly.
        let text = "x\n---\n\t# c\n  memory_mib: \"512\"  \ncpu_count:a:2\r\n";
        assert_eq!(parse(text), config("512", "2", ""));
        // Later lines win, comments stay in values, an unterminated last line is ignored.
        let text = "---\nmemory_mib: 1\nmemory_mib: 2 # x\ncpu_pool: 1, 5\ncpu_count: 2";
        assert_eq!(parse(text), config("2 # x", "", "1, 5"));
        // Backslashes as bash `read` treats them.
        assert_eq!(
            parse("---\nmemory_mib: 5\\\n1\\2\ncpu_count: 2\n"),
            config("512", "2", "")
        );
        assert_eq!(
            parse("---\nmemory_mib: 1\n\n"),
            Err("Error in a.yaml:3 - unexpected: ".into())
        );
        let err = Err("Error in a.yaml:2 - unexpected: Memory_mib".into());
        assert_eq!(parse("---\nMemory_mib: 1\n"), err);
        let err = Err("Error in a.yaml:2 - missing value for cpu_count".into());
        assert_eq!(parse("---\ncpu_count: \"\n"), err);
        assert!(parse("memory_mib: 1\ncpu_count: 2\n")
            .unwrap_err()
            .contains("memory_mib"));
        assert!(parse("---\nmemory_mib: 1\n")
            .unwrap_err()
            .contains("either"));
        let text = "---\nmemory_mib: 1\ncpu_count: 2\ncpu_pool: 1\n";
        assert!(parse(text).unwrap_err().contains("conflicts"));
    }

    #[test]
    fn numbers() {
        assert_eq!(memory_bytes("512"), Ok(512 << 20));
        assert_eq!(memory_bytes("0512"), Ok(330 << 20));
        for bad in ["", "08", "1.5", " 512", "99999999999999"] {
            assert!(memory_bytes(bad).is_err(), "{}", bad);
        }
        assert_eq!(parse_cpus("2,3,6-9", 9), Some(vec![2, 3, 6, 7, 8, 9]));
        assert_eq!(parse_cpus(" ,1 05,\t2-3,\r\n", 9), Some(vec![1, 2, 3, 5]));
        assert_eq!(parse_cpus("1,6-N", 8), Some(vec![1, 6, 7, 8]));
        for bad in [
            "", ",", "3-1", "1-", "-1", "1-2-3", "+1", "N1", "all", "65536",
        ] {
            assert_eq!(parse_cpus(bad, 9), None, "{bad}");
        }
        assert_eq!(format_cpus(&[1, 2, 3, 5, 7, 8]), "1-3,5,7-8");
    }

    /// CPU c is on node `nodes[c]` and shares its core with `core(c)`.
    fn topology(nodes: &[u32], core: impl Fn(u32) -> Vec<u32>) -> Topology {
        let cpus = (0..nodes.len() as u32)
            .map(|id| Cpu {
                id,
                node: Some(nodes[id as usize]),
                siblings: core(id),
            })
            .collect();
        Topology::new(nodes.len(), cpus).unwrap()
    }

    /// Selects CPUs; reserving memory fails on `full` nodes.
    fn select(t: &Topology, count: &str, full: &[u32]) -> Result<Vec<u32>> {
        t.select(count, &mut |node, _| match full.contains(&node) {
            true => Err(format!("node {node} is full")),
            false => Ok(()),
        })
    }

    #[test]
    fn cpu_count_selection() {
        // Siblings N and N+4, as on x86.
        let x86 = topology(&[0; 8], |c| vec![c % 4, c % 4 + 4]);
        assert_eq!(select(&x86, "2", &[]), Ok(vec![1, 5]));
        assert_eq!(select(&x86, "6", &[]), Ok(vec![1, 5, 2, 6, 3, 7]));
        assert_eq!(select(&x86, "8", &[]), Err(ERR_NO_CPUS.into()));
        let err = Err("The CPU count is not multiple of 2 (threads per core).".into());
        assert_eq!(select(&x86, "3", &[]), err);
        let err = Err("Provided CPU count is higher than available CPUs - 8.".into());
        assert_eq!(select(&x86, "9", &[]), err);
        let err = Err("Provided CPU count is not higher than 0.".into());
        assert_eq!(select(&x86, "0", &[]), err);
        assert_eq!(select(&x86, "99999999999999999999", &[]), err);
        let err = Err("The CPU count value (-2) is invalid.".into());
        assert_eq!(select(&x86, "-2", &[]), err);
        // Adjacent siblings: CPU 1 is the rest of CPU 0's core.
        let adjacent = topology(&[0; 8], |c| vec![c & !1, c | 1]);
        assert_eq!(select(&adjacent, "4", &[]), Ok(vec![2, 3, 4, 5]));
        // Two nodes with siblings N and N+8: node 0 has CPUs 0-3 and 8-11.
        let numa = topology(&[0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1], |c| {
            vec![c % 8, c % 8 + 8]
        });
        assert_eq!(select(&numa, "4", &[]), Ok(vec![1, 9, 2, 10]));
        assert_eq!(select(&numa, "4", &[0]), Ok(vec![4, 12, 5, 13]));
        assert_eq!(
            select(&numa, "8", &[]),
            Ok(vec![4, 12, 5, 13, 6, 14, 7, 15])
        );
        assert_eq!(select(&numa, "4", &[0, 1]), Err("node 1 is full".into()));
        // Node 0 cannot fit 8 CPUs, so node 1's memory error is the last one.
        assert_eq!(select(&numa, "8", &[1]), Err("node 1 is full".into()));
        // One thread per core, as on Graviton.
        let arm = topology(&[0; 4], |c| vec![c]);
        assert_eq!(select(&arm, "3", &[]), Ok(vec![1, 2, 3]));
        assert_eq!(select(&arm, "4", &[]), Err(ERR_NO_CPUS.into()));
    }

    /// Reserves `mib` over pages of `kib` sizes that start at `start` and of which
    /// the kernel grants at most `cap`. Returns the result and the final counts.
    fn split(kib: &[i128], cap: &[i128], start: &[i128], mib: i128) -> (Result<()>, Vec<i128>) {
        let sizes: Vec<(String, i128)> = kib.iter().map(|k| (format!("{k}kB"), k << 10)).collect();
        let mut counts = start.to_vec();
        let result = reserve(&sizes, mib << 20, &mut |i, count| {
            if let Some(count) = count {
                counts[i] = count.min(cap[i]);
            }
            Ok(counts[i])
        });
        (result, counts)
    }

    #[test]
    fn hugepages() {
        let x86 = [1 << 20, 2048];
        let any = [i128::MAX; 4];
        assert_eq!(split(&x86, &any, &[0, 0], 1536), (Ok(()), vec![1, 256]));
        // Old pages are cleared, and the request is rounded up to 2 MiB.
        assert_eq!(split(&x86, &any, &[3, 7], 513), (Ok(()), vec![0, 257]));
        assert_eq!(split(&x86, &any, &[0, 0], 0), (Ok(()), vec![0, 1]));
        // Without 1 GiB pages the 2 MiB pages cover all of it.
        assert_eq!(
            split(&x86, &[0, i128::MAX], &[0, 0], 2048),
            (Ok(()), vec![0, 1024])
        );
        let arm = [1 << 20, 32768, 2048, 64];
        assert_eq!(split(&arm, &any, &[0; 4], 1100), (Ok(()), vec![1, 2, 6, 0]));
        // Too few pages: back to the previous reservation.
        let failed = Err(ERR_INSUFFICIENT_MEMORY.into());
        assert_eq!(
            split(&x86, &[1, 10], &[1, 5], 2048),
            (failed.clone(), vec![1, 5])
        );
        assert_eq!(split(&[], &[], &[], 512).0, failed);
    }

    /// A sysfs tree with CPUs 0-7 (siblings N and N+4) on node 0 and 1 GiB and 2 MiB pages.
    fn sysfs() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let put = |path: &str, text: &str| {
            let path = dir.path().join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        };
        put(POOL_FILE, "dynamic\n");
        put("devices/system/cpu/possible", "0-7\n");
        put("devices/system/cpu/present", "0-7\n");
        put("devices/system/cpu/online", "0-7\n");
        for c in 0..8 {
            let siblings = format!("{},{}\n", c % 4, c % 4 + 4);
            put(
                &format!("devices/system/cpu/cpu{c}/topology/thread_siblings_list"),
                &siblings,
            );
            fs::create_dir_all(dir.path().join(format!("devices/system/cpu/cpu{c}/node0")))
                .unwrap();
        }
        for size in ["1048576kB", "2048kB"] {
            put(
                &format!("devices/system/node/node0/hugepages/hugepages-{size}/nr_hugepages"),
                "0\n",
            );
        }
        dir
    }

    #[test]
    fn allocates_through_sysfs() {
        let sys = sysfs();
        let sys = sys.path();
        let allocate = |text: &str| {
            fs::write(sys.join("allocator.yaml"), text).unwrap();
            run(sys, &sys.join("allocator.yaml"))
        };
        let state = || {
            let read = |path: String| fs::read_to_string(sys.join(path)).unwrap();
            let pages = |size| {
                read(format!(
                    "devices/system/node/node0/hugepages/{size}/nr_hugepages"
                ))
            };
            [
                read(POOL_FILE.into()),
                pages("hugepages-1048576kB"),
                pages("hugepages-2048kB"),
            ]
        };
        allocate("---\nmemory_mib: 1536\ncpu_count: 4\n").unwrap();
        assert_eq!(state(), ["1-2,5-6\n", "1\n", "256\n"]);
        allocate("---\nmemory_mib: 2\ncpu_pool: 3 7-N\n").unwrap();
        assert_eq!(state(), ["3,7\n", "0\n", "1\n"]);
        let long: String = (1..600).step_by(2).map(|c| format!("{c},")).collect();
        let err = allocate(&format!("---\nmemory_mib: 2\ncpu_pool: {long}\n")).unwrap_err();
        assert!(err.contains("at most 510"), "{}", err);
        assert_eq!(state()[0], "\n");
        // CPU 3 on another node, CPU 2 without a node link.
        let cpu = |c: u32, node: &str| sys.join(format!("devices/system/cpu/cpu{c}/{node}"));
        fs::rename(cpu(3, "node0"), cpu(3, "node1")).unwrap();
        let err = allocate("---\nmemory_mib: 2\ncpu_pool: 1,3\n");
        assert_eq!(err, Err(ERR_INVALID_NODE.into()));
        fs::remove_dir(cpu(2, "node0")).unwrap();
        let err = allocate("---\nmemory_mib: 2\ncpu_pool: 2,6\n");
        assert_eq!(err, Err(ERR_MISSING_NODE.into()));
        fs::remove_dir_all(sys.join("module")).unwrap();
        let err = allocate("---\nmemory_mib: 2\ncpu_count: 2\n");
        assert_eq!(err, Err(ERR_NO_POOL_FILE.into()));
    }
}
