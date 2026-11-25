//! Opt-in traffic accounting. The hub still receives its native wire fields.
//! Only durable counters are exposed: a crash cannot roll a reported total back.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::time::Instant;

use crate::collect::Ifaces;

const PPM: u64 = 1_000_000;
// The hub parses these fields as signed SQLite integers.
const MAX_BYTES: u64 = i64::MAX as u64;
const MAX_FILE: u64 = 4 * 1024 * 1024;
const LEGACY_SCHEMA: u32 = 1;
const SCHEMA: u32 = 2;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Report {
    #[default]
    Raw,
    Billing,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Weights {
    pub rx_to_in_ppm: u64,
    pub rx_to_out_ppm: u64,
    pub tx_to_in_ppm: u64,
    pub tx_to_out_ppm: u64,
}

impl Default for Weights {
    fn default() -> Self {
        Self { rx_to_in_ppm: PPM, rx_to_out_ppm: 0, tx_to_in_ppm: 0, tx_to_out_ppm: PPM }
    }
}

impl Weights {
    fn validate(&self) -> Result<()> {
        ensure!(
            [self.rx_to_in_ppm, self.rx_to_out_ppm, self.tx_to_in_ppm, self.tx_to_out_ppm]
                .iter()
                .all(|v| *v <= u32::MAX as u64),
            "weight exceeds u32 ppm limit"
        );
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub state_file: PathBuf,
    #[serde(default)]
    pub report: Report,
    #[serde(default = "strict_default")]
    pub strict: bool,
    #[serde(default = "checkpoint_default")]
    pub checkpoint_secs: u64,
    #[serde(default)]
    pub weights: BTreeMap<String, Weights>,
}

fn strict_default() -> bool {
    true
}
fn checkpoint_default() -> u64 {
    30
}

impl Config {
    pub fn load(path: &str, ifaces: &Ifaces) -> Result<Self> {
        let config: Self = read_json(Path::new(path))?;
        config.validate(ifaces)?;
        Ok(config)
    }

    fn validate(&self, ifaces: &Ifaces) -> Result<()> {
        ensure!(self.state_file.is_absolute(), "state_file must be absolute");
        ensure!(self.state_file.file_name().is_some(), "state_file needs a filename");
        ensure!(
            !self.state_file.extension().is_some_and(|ext| ext == "lock" || ext == "tmp"),
            "state_file must not use the reserved .lock or .tmp suffix"
        );
        ensure!((5..=3600).contains(&self.checkpoint_secs), "checkpoint_secs must be 5..3600");
        ifaces.validate_names()?;
        for (name, weights) in &self.weights {
            validate_name(name)?;
            weights.validate()?;
        }
        Ok(())
    }

    fn weight(&self, name: &str) -> Weights {
        self.weights.get(name).copied().unwrap_or_default()
    }
}

pub fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 15
            && !matches!(name, "." | "..")
            && !name.starts_with('-')
            && name.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)),
        "invalid full interface name: {name:?}"
    );
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    ifindex: u32,
    iflink: u32,
    address: String,
    link_type: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Link {
    identity: Identity,
    rx: u64,
    tx: u64,
    weights: Weights,
}

#[derive(Clone, Debug, Serialize)]
pub struct Sample {
    kernel_boot_id: String,
    netns: String,
    links: BTreeMap<String, Link>,
    missing: Vec<String>,
    unused_weights: Vec<String>,
    native_epoch: String,
}

fn text(path: impl AsRef<Path>) -> Result<String> {
    Ok(fs::read_to_string(path.as_ref())
        .with_context(|| format!("read {}", path.as_ref().display()))?
        .trim()
        .into())
}

fn identity(sys: &Path, name: &str) -> Result<Identity> {
    validate_name(name)?;
    let dir = sys.join(name);
    let identity = Identity {
        ifindex: text(dir.join("ifindex"))?.parse()?,
        iflink: text(dir.join("iflink"))?.parse()?,
        address: text(dir.join("address"))?,
        link_type: text(dir.join("type"))?.parse()?,
    };
    ensure!(identity.ifindex > 0 && identity.iflink > 0, "invalid interface identity for {name}");
    Ok(identity)
}

/// Unlike the upstream best-effort parser, accounting must reject a partial
/// read rather than commit zeros or silently drop one interface.
fn counters(dev: &str) -> Result<BTreeMap<String, (u64, u64)>> {
    let mut lines = dev.lines();
    ensure!(lines.next().is_some_and(|s| s.contains("Inter-")), "bad /proc/net/dev header");
    ensure!(lines.next().is_some_and(|s| s.contains("bytes")), "bad /proc/net/dev columns");
    let mut result = BTreeMap::new();
    for line in lines {
        let (name, values) = line.split_once(':').context("bad /proc/net/dev row")?;
        let name = name.trim();
        let values = values.split_whitespace().map(str::parse::<u64>).collect::<Result<Vec<_>, _>>()?;
        ensure!(values.len() == 16, "bad /proc/net/dev field count for {name}");
        ensure!(
            result.insert(name.to_owned(), (values[0], values[8])).is_none(),
            "duplicate interface {name}"
        );
    }
    ensure!(!result.is_empty(), "/proc/net/dev contains no interfaces");
    Ok(result)
}

fn sample(ifaces: &Ifaces, config: Option<&Config>) -> Result<Sample> {
    sample_at(ifaces, config, Path::new("/proc"), Path::new("/sys/class/net"))
}

fn sample_at(ifaces: &Ifaces, config: Option<&Config>, proc: &Path, sys: &Path) -> Result<Sample> {
    let boot = text(proc.join("sys/kernel/random/boot_id"))?;
    ensure!(!boot.is_empty(), "empty kernel boot_id");
    let ns = fs::metadata(proc.join("self/ns/net"))?;
    let netns = format!("{}:{}", ns.dev(), ns.ino());
    let first = counters(&text(proc.join("net/dev"))?)?;
    let selected = |dev: &BTreeMap<String, (u64, u64)>| -> Vec<String> {
        dev.keys().filter(|n| ifaces.counts(sys, n)).cloned().collect()
    };
    let names = selected(&first);
    let mut identities = BTreeMap::new();
    for name in &names {
        identities.insert(name.clone(), identity(sys, name)?);
    }
    let dev = counters(&text(proc.join("net/dev"))?)?;
    ensure!(selected(&dev) == names, "interface selection changed during sampling; retry");
    let mut links = BTreeMap::new();
    for name in &names {
        let id = identity(sys, name)?;
        ensure!(identities[name] == id, "interface {name} changed identity during sampling; retry");
        let (rx, tx) = dev[name];
        links.insert(
            name.clone(),
            Link { identity: id, rx, tx, weights: config.map_or_else(Weights::default, |c| c.weight(name)) },
        );
    }
    let ns_after = fs::metadata(proc.join("self/ns/net"))?;
    ensure!(
        netns == format!("{}:{}", ns_after.dev(), ns_after.ino())
            && boot == text(proc.join("sys/kernel/random/boot_id"))?,
        "boot/network namespace changed during sampling"
    );
    let missing = ifaces.missing(dev.keys().map(String::as_str));
    let unused_weights = config
        .map_or_else(Vec::new, |c| c.weights.keys().filter(|n| !links.contains_key(*n)).cloned().collect());
    let native_epoch = crate::collect::epoch(&boot, names.iter().map(String::as_str));
    Ok(Sample { kernel_boot_id: boot, netns, links, missing, unused_weights, native_epoch })
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Pair {
    pub rx: u64,
    pub tx: u64,
}

impl Pair {
    fn add(&mut self, delta: Self) -> Result<()> {
        self.rx = self
            .rx
            .checked_add(delta.rx)
            .filter(|v| *v <= MAX_BYTES)
            .context("RX total overflow (hub i64 limit)")?;
        self.tx = self
            .tx
            .checked_add(delta.tx)
            .filter(|v| *v <= MAX_BYTES)
            .context("TX total overflow (hub i64 limit)")?;
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Seed {
    pub boot_id: String,
    pub net_rx_total: u64,
    pub net_tx_total: u64,
    pub note: String,
}

impl Seed {
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.boot_id.is_empty()
                && self.boot_id.len() <= 256
                && !self.boot_id.contains(char::is_whitespace),
            "seed needs the exact last reported boot_id"
        );
        ensure!(
            self.net_rx_total <= MAX_BYTES && self.net_tx_total <= MAX_BYTES,
            "seed exceeds hub i64 limit"
        );
        ensure!(!self.note.trim().is_empty(), "seed note must explain counter provenance");
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    schema: u32,
    seed: Seed,
    report: Report,
    raw: Pair,
    billing: Pair,
    /// Schema 1 carries fractions for all interfaces together.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    remainder: Option<Pair>,
    /// Schema 2 carries fractions by name, including absent interfaces.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    remainders: Option<BTreeMap<String, Pair>>,
    kernel_boot_id: String,
    netns: String,
    links: BTreeMap<String, Link>,
    checkpoint_unix: u64,
    checkpoints: u64,
    resets: u64,
    baselines: u64,
}

// Missing fields select the other schema. An explicitly supplied null is invalid.
fn present<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

impl State {
    fn new(seed: Seed, report: Report) -> Result<Self> {
        seed.validate()?;
        let total = Pair { rx: seed.net_rx_total, tx: seed.net_tx_total };
        Ok(Self {
            schema: SCHEMA,
            seed,
            report,
            raw: total,
            billing: total,
            remainder: None,
            remainders: Some(BTreeMap::new()),
            kernel_boot_id: String::new(),
            netns: String::new(),
            links: BTreeMap::new(),
            checkpoint_unix: 0,
            checkpoints: 0,
            resets: 0,
            baselines: 0,
        })
    }

    fn validate(&self) -> Result<()> {
        match (self.schema, &self.remainder, &self.remainders) {
            (LEGACY_SCHEMA, Some(remainder), None) => {
                ensure!(remainder.rx < PPM && remainder.tx < PPM, "invalid shared fractional remainder");
            }
            (SCHEMA, None, Some(remainders)) => {
                for (name, remainder) in remainders {
                    validate_name(name)?;
                    ensure!(
                        remainder.rx < PPM && remainder.tx < PPM,
                        "invalid fractional remainder for {name}"
                    );
                }
            }
            (LEGACY_SCHEMA | SCHEMA, _, _) => bail!("traffic state remainder fields do not match its schema"),
            _ => bail!("unsupported traffic state schema"),
        }
        self.seed.validate()?;
        for total in [self.raw, self.billing] {
            ensure!(
                total.rx >= self.seed.net_rx_total
                    && total.tx >= self.seed.net_tx_total
                    && total.rx <= MAX_BYTES
                    && total.tx <= MAX_BYTES,
                "invalid state totals"
            );
        }
        for (name, link) in &self.links {
            validate_name(name)?;
            link.weights.validate()?;
            ensure!(link.identity.ifindex > 0 && link.identity.iflink > 0, "invalid interface identity");
        }
        Ok(())
    }

    fn output(&self) -> Pair {
        match self.report {
            Report::Raw => self.raw,
            Report::Billing => self.billing,
        }
    }

    fn apply(&mut self, sample: &Sample) -> Result<Pair> {
        let same_host = self.kernel_boot_id == sample.kernel_boot_id && self.netns == sample.netns;
        let mut raw = Pair::default();
        let mut shared = self.remainder.map(|r| (u128::from(r.rx), u128::from(r.tx)));
        for (name, link) in &sample.links {
            let previous = self
                .links
                .get(name)
                .filter(|p| same_host && p.identity == link.identity && p.weights == link.weights);
            if let Some(prev) = previous {
                let rx = link.rx.checked_sub(prev.rx);
                let tx = link.tx.checked_sub(prev.tx);
                self.resets = self
                    .resets
                    .checked_add(u64::from(rx.is_none()) + u64::from(tx.is_none()))
                    .context("reset count overflow")?;
                let delta = Pair { rx: rx.unwrap_or(0), tx: tx.unwrap_or(0) };
                raw.add(delta)?;
                let w = link.weights;
                let input = numerator(delta, w.rx_to_in_ppm, w.tx_to_in_ppm);
                let output = numerator(delta, w.rx_to_out_ppm, w.tx_to_out_ppm);
                if let Some((total_in, total_out)) = &mut shared {
                    *total_in = total_in.checked_add(input).context("weighted input overflow")?;
                    *total_out = total_out.checked_add(output).context("weighted output overflow")?;
                } else if let Some(remainders) = &mut self.remainders {
                    let carry = remainders.get(name).copied().unwrap_or_default();
                    let (bytes, remainder) =
                        split_weighted(input + u128::from(carry.rx), output + u128::from(carry.tx))?;
                    self.billing.add(bytes)?;
                    if remainder == Pair::default() {
                        remainders.remove(name);
                    } else {
                        remainders.insert(name.clone(), remainder);
                    }
                }
            } else {
                self.baselines = self.baselines.checked_add(1).context("baseline count overflow")?;
            }
        }
        if let Some((input, output)) = shared {
            let (bytes, remainder) = split_weighted(input, output)?;
            self.billing.add(bytes)?;
            self.remainder = Some(remainder);
        }
        self.raw.add(raw)?;
        self.kernel_boot_id.clone_from(&sample.kernel_boot_id);
        self.netns.clone_from(&sample.netns);
        self.links.clone_from(&sample.links);
        Ok(raw)
    }
}

fn numerator(delta: Pair, rx_weight: u64, tx_weight: u64) -> u128 {
    u128::from(delta.rx) * u128::from(rx_weight) + u128::from(delta.tx) * u128::from(tx_weight)
}

fn split_weighted(input: u128, output: u128) -> Result<(Pair, Pair)> {
    let scale = u128::from(PPM);
    Ok((
        Pair {
            rx: u64::try_from(input / scale).context("weighted input byte count overflow")?,
            tx: u64::try_from(output / scale).context("weighted output byte count overflow")?,
        },
        Pair { rx: (input % scale) as u64, tx: (output % scale) as u64 },
    ))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file).take(MAX_FILE + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX_FILE, "{} exceeds size limit", path.display());
    serde_json::from_slice(&bytes).with_context(|| format!("invalid JSON in {}", path.display()))
}

fn private_file(path: &Path, write: bool, create: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(write)
        .create(create)
        .mode(0o600)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)
        .with_context(|| format!("open private file {}", path.display()))?;
    let meta = file.metadata()?;
    // A status reader may have opened the previous inode just before rename.
    ensure!(
        meta.is_file()
            && meta.permissions().mode() & 0o077 == 0
            && meta.nlink() <= 1
            && (!write || meta.nlink() == 1),
        "{} must be a private regular file (0600, no hard links)",
        path.display()
    );
    Ok(file)
}

fn read_state(path: &Path) -> Result<State> {
    let mut file = private_file(path, false, false)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file).take(MAX_FILE + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX_FILE, "state exceeds size limit");
    let state: State = serde_json::from_slice(&bytes).context("invalid traffic state JSON")?;
    state.validate()?;
    Ok(state)
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn lock(path: &Path) -> Result<File> {
    let parent = path.parent().context("state needs a parent directory")?;
    if !parent.exists() {
        fs::DirBuilder::new().recursive(true).mode(0o700).create(parent)?;
    }
    let meta = fs::symlink_metadata(parent)?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink() && meta.permissions().mode() & 0o077 == 0,
        "state directory must be private (0700), not a symlink"
    );
    let file = private_file(&sidecar(path, ".lock"), true, true)?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .context("traffic state is locked by another instance")?;
    Ok(file)
}

fn save(path: &Path, state: &State) -> Result<()> {
    let tmp = sidecar(path, ".tmp");
    // A stale temporary file is never trusted; the lock covers its removal.
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
    let bytes = serde_json::to_vec(state)?;
    ensure!(bytes.len() as u64 <= MAX_FILE, "state exceeds size limit");
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    File::open(path.parent().context("state needs parent")?)?.sync_all()?;
    Ok(())
}

pub struct Ledger {
    config: Config,
    _lock: File,
    pending: State,
    durable: State,
    last_save: Instant,
    last_sample: Option<Instant>,
}

pub struct Reading {
    pub epoch: String,
    pub total: Pair,
    pub rate: Pair,
}

impl Ledger {
    pub fn open(config: Config) -> Result<Self> {
        let guard = lock(&config.state_file)?;
        let durable = read_state(&config.state_file).context("read the traffic checkpoint")?;
        ensure!(
            durable.report == config.report,
            "report mode changed; stop and explicitly migrate with the last reported epoch/totals"
        );
        let mut pending = durable.clone();
        // Schema 1 resumes at the durable checkpoint. State::apply gates each
        // direction by the saved host, link identity, weights and counter.
        // Schema 2 keeps its fresh-baseline behavior on process restart.
        if pending.schema == SCHEMA {
            pending.links.clear();
        }
        Ok(Self { config, _lock: guard, pending, durable, last_save: Instant::now(), last_sample: None })
    }

    pub fn start(mut self, ifaces: Ifaces, interval: Duration) -> watch::Receiver<Option<Reading>> {
        let (tx, rx) = watch::channel(None);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut last_error = None;
            loop {
                tokio::select! {
                    _ = tx.closed() => break,
                    _ = ticker.tick() => {}
                }
                match self.collect(&ifaces) {
                    Ok(reading) => {
                        tx.send_replace(Some(reading));
                        last_error = None;
                    }
                    Err(error) => {
                        tx.send_replace(None);
                        let message = format!("{error:#}");
                        if last_error.as_ref() != Some(&message) {
                            eprintln!("traffic sample unavailable: {message}");
                            last_error = Some(message);
                        }
                    }
                }
            }
        });
        rx
    }

    fn collect(&mut self, ifaces: &Ifaces) -> Result<Reading> {
        let sample = sample(ifaces, Some(&self.config)).and_then(|sample| {
            ensure!(
                !self.config.strict || sample.missing.is_empty(),
                "required interfaces missing: {}",
                sample.missing.join(",")
            );
            Ok(sample)
        });
        match sample {
            Ok(sample) => self.observe(&sample, Instant::now()),
            Err(error) => {
                self.pending.links.clear();
                self.last_sample = None;
                Err(error)
            }
        }
    }

    fn observe(&mut self, sample: &Sample, now: Instant) -> Result<Reading> {
        let mut next = self.pending.clone();
        let delta = next.apply(sample)?;
        let secs = self.last_sample.map_or(0.0, |t| now.saturating_duration_since(t).as_secs_f64());
        let rate = if secs > 0.0 {
            Pair { rx: (delta.rx as f64 / secs) as u64, tx: (delta.tx as f64 / secs) as u64 }
        } else {
            Pair::default()
        };
        self.pending = next;
        self.last_sample = Some(now);
        if now.saturating_duration_since(self.last_save) >= Duration::from_secs(self.config.checkpoint_secs) {
            let mut checkpoint = self.pending.clone();
            checkpoint.checkpoint_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            checkpoint.checkpoints =
                checkpoint.checkpoints.checked_add(1).context("checkpoint count overflow")?;
            save(&self.config.state_file, &checkpoint)?;
            self.pending.checkpoint_unix = checkpoint.checkpoint_unix;
            self.pending.checkpoints = checkpoint.checkpoints;
            self.durable = checkpoint;
            self.last_save = now;
        }
        Ok(Reading { epoch: self.durable.seed.boot_id.clone(), total: self.durable.output(), rate })
    }
}

pub fn initialize(config: &Config, seed_path: &str) -> Result<()> {
    let _guard = lock(&config.state_file)?;
    match fs::symlink_metadata(&config.state_file) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
        Ok(_) => bail!("state already exists; initialization never overwrites a ledger"),
    }
    let seed: Seed = read_json(Path::new(seed_path))?;
    let state = State::new(seed, config.report)?;
    save(&config.state_file, &state)?;
    println!(
        "{}",
        serde_json::to_string_pretty(
            &serde_json::json!({"schema":SCHEMA,"initialized":config.state_file,"state":state})
        )?
    );
    Ok(())
}

/// Offline diagnostics open no locks, write no files, and generate no identity.
pub fn check(ifaces: &Ifaces, config: Option<&Config>) -> Result<()> {
    let sample = sample(ifaces, config)?;
    let valid = config.is_none_or(|c| !c.strict) || sample.missing.is_empty();
    println!(
        "{}",
        serde_json::to_string_pretty(
            &serde_json::json!({"schema":1,"valid":valid,"iface":ifaces.spec(),"config":config,"sample":sample,"units":{"counters":"bytes","weights":"integer ppm (1000000 = 1)"}})
        )?
    );
    ensure!(valid, "required interfaces missing; see JSON missing list (no fallback)");
    Ok(())
}

pub fn status(config: &Config) -> Result<()> {
    let state = read_state(&config.state_file)?;
    ensure!(state.report == config.report, "report mode differs from state");
    println!(
        "{}",
        serde_json::to_string_pretty(
            &serde_json::json!({"schema":state.schema,"durable_only":true,"state":state,"report_totals":state.output()})
        )?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "monitor-traffic-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
            Self(dir)
        }
        fn config(&self) -> Config {
            Config {
                state_file: self.0.join("state.json"),
                report: Report::Billing,
                strict: true,
                checkpoint_secs: 5,
                weights: BTreeMap::new(),
            }
        }
        fn ledger(&self) -> Ledger {
            let config = self.config();
            save(&config.state_file, &state()).unwrap();
            Ledger::open(config).unwrap()
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn state() -> State {
        State::new(
            Seed {
                boot_id: "original-kernel/original-set".into(),
                net_rx_total: 1_000_000,
                net_tx_total: 2_000_000,
                note: "synthetic last native report, not hub lifetime totals".into(),
            },
            Report::Billing,
        )
        .unwrap()
    }
    fn sample(links: &[(&str, u64, u64, Weights)]) -> Sample {
        Sample {
            kernel_boot_id: "kernel-a".into(),
            netns: "1:2".into(),
            native_epoch: "ignored".into(),
            missing: Vec::new(),
            unused_weights: Vec::new(),
            links: links
                .iter()
                .map(|(name, rx, tx, weights)| {
                    (
                        name.to_string(),
                        Link {
                            identity: Identity {
                                ifindex: 2,
                                iflink: 2,
                                address: "00:11:22:33:44:55".into(),
                                link_type: 1,
                            },
                            rx: *rx,
                            tx: *tx,
                            weights: *weights,
                        },
                    )
                })
                .collect(),
        }
    }
    fn identity_weights() -> Weights {
        Weights::default()
    }
    fn half() -> Weights {
        Weights { rx_to_in_ppm: 500_000, tx_to_out_ppm: 500_000, ..Weights::default() }
    }

    fn legacy_state(carry: Pair) -> State {
        State { schema: LEGACY_SCHEMA, remainder: Some(carry), remainders: None, ..state() }
    }

    #[test]
    fn legacy_checkpoint_resumes_both_directions_and_writes_the_legacy_format() {
        let tmp = Temp::new();
        let config = tmp.config();
        let relay =
            Weights { rx_to_in_ppm: 0, rx_to_out_ppm: 250_000, tx_to_in_ppm: 250_000, tx_to_out_ppm: 0 };
        let first = sample(&[("primary", 100, 200, half()), ("relay", 500, 600, relay)]);
        let mut old = legacy_state(Pair { rx: 500_000, tx: 250_000 });
        old.raw = Pair { rx: 10_000_000, tx: 20_000_000 };
        old.billing = Pair { rx: 30_000_000, tx: 40_000_000 };
        old.apply(&first).unwrap();
        old.checkpoints = 25;
        save(&config.state_file, &old).unwrap();
        let before = fs::read(&config.state_file).unwrap();
        let mut ledger = Ledger::open(config.clone()).unwrap();
        assert_eq!(serde_json::to_vec(&ledger.pending).unwrap(), before);
        let t = ledger.last_save;
        let second = sample(&[("primary", 101, 201, half()), ("relay", 501, 601, relay)]);
        let reading = ledger.observe(&second, t).unwrap();
        assert_eq!(reading.epoch, old.seed.boot_id);
        assert_eq!(reading.total, old.billing);
        assert_eq!(reading.rate, Pair::default());
        assert_eq!(ledger.pending.raw, Pair { rx: 10_000_002, tx: 20_000_002 });
        assert_eq!(ledger.pending.billing, Pair { rx: 30_000_001, tx: 40_000_001 });
        assert_eq!(ledger.pending.remainder, Some(Pair { rx: 250_000, tx: 0 }));
        assert_eq!(fs::read(&config.state_file).unwrap(), before);

        ledger.observe(&second, t + Duration::from_secs(5)).unwrap();
        let saved: serde_json::Value = read_json(&config.state_file).unwrap();
        assert_eq!(saved["schema"], LEGACY_SCHEMA);
        assert!(saved.get("remainders").is_none());
        assert_eq!(saved["remainder"], serde_json::json!({"rx":250000,"tx":0}));
        drop(ledger);

        let mut ledger = Ledger::open(config).unwrap();
        let third = sample(&[("primary", 102, 202, half()), ("relay", 502, 602, relay)]);
        ledger.observe(&third, ledger.last_save + Duration::from_secs(5)).unwrap();
        assert_eq!(ledger.durable.raw, Pair { rx: 10_000_004, tx: 20_000_004 });
        assert_eq!(ledger.durable.billing, Pair { rx: 30_000_002, tx: 40_000_001 });
        assert_eq!(ledger.durable.remainder, Some(Pair { rx: 0, tx: 750_000 }));
        assert_eq!(ledger.durable.checkpoints, old.checkpoints + 2);
        assert_eq!(ledger.durable.baselines, old.baselines);
        assert_eq!(ledger.durable.resets, old.resets);
    }

    #[test]
    fn legacy_restart_drops_only_incomparable_intervals() {
        let tmp = Temp::new();
        let config = tmp.config();
        let w = half();
        let mut old = legacy_state(Pair { rx: 125_000, tx: 250_000 });
        old.apply(&sample(&[("reset", 100, 200, w), ("recreated", 300, 400, w), ("changed", 500, 600, w)]))
            .unwrap();
        save(&config.state_file, &old).unwrap();
        let mut ledger = Ledger::open(config).unwrap();
        let t = ledger.last_save;
        let mut next = sample(&[
            ("reset", 10, 203, w),
            ("recreated", 3000, 4000, w),
            ("changed", 5000, 6000, Weights::default()),
        ]);
        next.links.get_mut("recreated").unwrap().identity.ifindex = 22;
        ledger.observe(&next, t).unwrap();
        assert_eq!(ledger.pending.raw, Pair { rx: old.raw.rx, tx: old.raw.tx + 3 });
        assert_eq!(ledger.pending.billing, Pair { rx: old.billing.rx, tx: old.billing.tx + 1 });
        assert_eq!(ledger.pending.remainder, Some(Pair { rx: 125_000, tx: 750_000 }));
        assert_eq!(ledger.pending.resets, old.resets + 1);
        assert_eq!(ledger.pending.baselines, old.baselines + 2);

        let before = ledger.pending.raw;
        next.netns = "different-namespace".into();
        next.links.get_mut("reset").unwrap().tx += 1000;
        ledger.observe(&next, t + Duration::from_secs(1)).unwrap();
        assert_eq!(ledger.pending.raw, before);
        next.kernel_boot_id = "different-boot".into();
        next.links.get_mut("reset").unwrap().tx += 1000;
        ledger.observe(&next, t + Duration::from_secs(2)).unwrap();
        assert_eq!(ledger.pending.raw, before);

        assert!(ledger.collect(&Ifaces::parse("missing-test0").unwrap()).is_err());
        assert!(ledger.pending.links.is_empty());
        assert_eq!(read_state(&ledger.config.state_file).unwrap().raw, old.raw);
        next.links.get_mut("reset").unwrap().tx += 1000;
        ledger.observe(&next, t + Duration::from_secs(5)).unwrap();
        assert_eq!(ledger.durable.raw, before);
        assert_eq!(ledger.durable.seed.boot_id, old.seed.boot_id);
    }

    #[test]
    fn four_directions_apply_only_deltas() {
        let mut s = state();
        let p = Weights::default();
        let r =
            Weights { rx_to_in_ppm: 0, rx_to_out_ppm: PPM, tx_to_in_ppm: 500_000, tx_to_out_ppm: 2 * PPM };
        s.apply(&sample(&[("primary", 90_000_000, 80_000_000, p), ("relay", 70_000_000, 60_000_000, r)]))
            .unwrap();
        s.apply(&sample(&[("primary", 90_000_100, 80_000_200, p), ("relay", 70_000_300, 60_000_400, r)]))
            .unwrap();
        assert_eq!(s.raw, Pair { rx: 1_000_400, tx: 2_000_600 });
        assert_eq!(s.billing, Pair { rx: 1_000_300, tx: 2_001_300 });
        assert_eq!(s.output(), s.billing);
        s.report = Report::Raw;
        assert_eq!(s.output(), s.raw);
        assert_eq!(s.seed.boot_id, "original-kernel/original-set");
    }

    #[test]
    fn splitting_samples_preserves_fractional_bytes_and_json_roundtrip() {
        let mut whole = state();
        let w = half();
        whole.apply(&sample(&[("eth0", 0, 0, w)])).unwrap();
        let mut split = whole.clone();
        whole.apply(&sample(&[("eth0", 17, 29, w)])).unwrap();
        for i in 1..=29 {
            split.apply(&sample(&[("eth0", i.min(17), i, w)])).unwrap();
            split = serde_json::from_str(&serde_json::to_string(&split).unwrap()).unwrap();
        }
        assert_eq!(whole.raw, split.raw);
        assert_eq!(whole.billing, split.billing);
        assert_eq!(whole.remainders, split.remainders);
        assert_eq!(split.remainders.as_ref().unwrap()["eth0"], Pair { rx: 500_000, tx: 500_000 });
    }

    #[test]
    fn each_interface_keeps_its_own_remainder_even_while_absent() {
        let mut s = state();
        let w = half();
        s.apply(&sample(&[("eth0", 0, 0, w), ("eth1", 0, 0, w)])).unwrap();
        s.apply(&sample(&[("eth0", 1, 1, w), ("eth1", 1, 1, w)])).unwrap();
        assert_eq!(s.billing, state().billing);
        let half_byte = Pair { rx: 500_000, tx: 500_000 };
        assert_eq!(s.remainders.as_ref().unwrap()["eth0"], half_byte);
        assert_eq!(s.remainders.as_ref().unwrap()["eth1"], half_byte);

        s.apply(&sample(&[("eth0", 2, 2, w)])).unwrap();
        assert_eq!(s.billing, Pair { rx: 1_000_001, tx: 2_000_001 });
        assert!(!s.remainders.as_ref().unwrap().contains_key("eth0"));
        assert_eq!(s.remainders.as_ref().unwrap()["eth1"], half_byte);
        s.apply(&sample(&[("eth0", 2, 2, w), ("eth1", 9000, 9000, w)])).unwrap();
        s.apply(&sample(&[("eth0", 2, 2, w), ("eth1", 9001, 9001, w)])).unwrap();
        assert_eq!(s.billing, Pair { rx: 1_000_002, tx: 2_000_002 });
        assert!(s.remainders.as_ref().unwrap().is_empty());
    }

    #[test]
    fn one_direction_reset_keeps_the_other_direction() {
        let mut s = state();
        let w = identity_weights();
        s.apply(&sample(&[("eth0", 900, 1000, w)])).unwrap();
        assert_eq!(s.apply(&sample(&[("eth0", 4, 1100, w)])).unwrap(), Pair { rx: 0, tx: 100 });
        assert_eq!(s.apply(&sample(&[("eth0", 14, 2, w)])).unwrap(), Pair { rx: 10, tx: 0 });
        assert_eq!(s.resets, 2);
    }

    #[test]
    fn disappearance_rename_recreation_boot_and_namespace_only_baseline() {
        let mut s = state();
        let w = identity_weights();
        s.apply(&sample(&[("eth0", 100, 200, w)])).unwrap();
        s.apply(&sample(&[])).unwrap();
        assert_eq!(s.apply(&sample(&[("eth0", 9_000_000, 8_000_000, w)])).unwrap(), Pair::default());
        let mut changed = sample(&[("eth0", 99_000_000, 88_000_000, w)]);
        changed.links.get_mut("eth0").unwrap().identity.ifindex = 7;
        assert_eq!(s.apply(&changed).unwrap(), Pair::default());
        changed.links.get_mut("eth0").unwrap().identity.address = "another-mac".into();
        assert_eq!(s.apply(&changed).unwrap(), Pair::default());
        let link = changed.links.remove("eth0").unwrap();
        changed.links.insert("wan".into(), link);
        assert_eq!(s.apply(&changed).unwrap(), Pair::default());
        changed.kernel_boot_id = "kernel-b".into();
        assert_eq!(s.apply(&changed).unwrap(), Pair::default());
        changed.netns = "4:5".into();
        assert_eq!(s.apply(&changed).unwrap(), Pair::default());
        assert_eq!(s.billing, state().billing);
        assert_eq!(s.seed.boot_id, state().seed.boot_id);
    }

    #[test]
    fn weight_changes_never_recalculate_history() {
        let mut s = state();
        let w = identity_weights();
        s.apply(&sample(&[("eth0", 0, 0, w)])).unwrap();
        s.apply(&sample(&[("eth0", 100, 100, w)])).unwrap();
        let before = s.billing;
        s.apply(&sample(&[("eth0", 100, 100, half())])).unwrap();
        assert_eq!(s.billing, before);
        s.apply(&sample(&[("eth0", 200, 200, half())])).unwrap();
        assert_eq!(s.billing, Pair { rx: before.rx + 50, tx: before.tx + 50 });
    }

    #[test]
    fn checkpoints_expose_only_durable_totals_and_restart_preserves_remainders() {
        let tmp = Temp::new();
        let mut l = tmp.ledger();
        let t = l.last_save;
        let a = sample(&[("eth0", 9000, 9000, half())]);
        let b = sample(&[("eth0", 9001, 9001, half())]);
        let c = sample(&[("eth0", 9003, 9003, half())]);
        assert_eq!(l.observe(&a, t).unwrap().total, state().billing);
        assert_eq!(l.observe(&b, t + Duration::from_secs(1)).unwrap().total, state().billing);
        let saved = l.observe(&c, t + Duration::from_secs(5)).unwrap();
        assert_eq!(saved.total, Pair { rx: 1_000_001, tx: 2_000_001 });
        assert_eq!(saved.rate, Pair::default()); // two bytes over four seconds
        assert_eq!(l.durable.remainders.as_ref().unwrap()["eth0"].rx, 500_000);
        l.observe(&sample(&[("eth0", 9999, 9999, half())]), t + Duration::from_secs(6)).unwrap();
        drop(l); // unsaved tail was never reported
        let mut l = Ledger::open(tmp.config()).unwrap();
        let t = l.last_save;
        assert_eq!(l.observe(&sample(&[("eth0", 999_999, 999_999, half())]), t).unwrap().total, saved.total);
        let after = l
            .observe(&sample(&[("eth0", 1_000_000, 1_000_000, half())]), t + Duration::from_secs(5))
            .unwrap();
        assert_eq!(after.epoch, saved.epoch);
        assert_eq!(after.total, Pair { rx: 1_000_002, tx: 2_000_002 });
        assert!(!l.durable.remainders.as_ref().unwrap().contains_key("eth0"));
    }

    #[test]
    fn overflow_and_failed_save_never_publish_or_commit_partial_counts() {
        let tmp = Temp::new();
        let mut l = tmp.ledger();
        let t = l.last_save;
        let w = identity_weights();
        l.observe(&sample(&[("eth0", 0, 0, w)]), t).unwrap();
        let before = serde_json::to_vec(&l.pending).unwrap();
        assert!(l.observe(&sample(&[("eth0", u64::MAX, u64::MAX, w)]), t + Duration::from_secs(5)).is_err());
        assert_eq!(serde_json::to_vec(&l.pending).unwrap(), before);
        fs::create_dir(sidecar(&l.config.state_file, ".tmp")).unwrap();
        assert!(l.observe(&sample(&[("eth0", 5, 10, w)]), t + Duration::from_secs(5)).is_err());
        assert_eq!(l.durable.raw, state().raw);
        assert_eq!(read_state(&l.config.state_file).unwrap().raw, state().raw);
        fs::remove_dir(sidecar(&l.config.state_file, ".tmp")).unwrap();
        let retry = l.observe(&sample(&[("eth0", 7, 15, w)]), t + Duration::from_secs(6)).unwrap();
        assert_eq!(retry.total, Pair { rx: 1_000_007, tx: 2_000_015 });
        assert_eq!(retry.rate, Pair { rx: 2, tx: 5 });
    }

    #[test]
    fn duplicate_instance_corrupt_missing_insecure_and_mode_change_fail_closed() {
        let tmp = Temp::new();
        let l = tmp.ledger();
        assert!(Ledger::open(tmp.config()).is_err());
        drop(l);
        let mut config = tmp.config();
        config.report = Report::Raw;
        assert!(Ledger::open(config).is_err());
        fs::write(&tmp.config().state_file, "{").unwrap();
        assert!(Ledger::open(tmp.config()).is_err());
        assert_eq!(fs::read_to_string(&tmp.config().state_file).unwrap(), "{");
        fs::remove_file(&tmp.config().state_file).unwrap();
        assert!(Ledger::open(tmp.config()).is_err());
        save(&tmp.config().state_file, &state()).unwrap();
        fs::set_permissions(&tmp.config().state_file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Ledger::open(tmp.config()).is_err());
    }

    #[test]
    fn invalid_weights_config_and_state_are_rejected() {
        let good = r#"{"rx_to_in_ppm":1000000,"rx_to_out_ppm":0,"tx_to_in_ppm":0,"tx_to_out_ppm":500000}"#;
        for bad in ["-1", "NaN", "1.5", "18446744073709551616"] {
            assert!(serde_json::from_str::<Weights>(&good.replace("500000", bad)).is_err());
        }
        let w: Weights = serde_json::from_str(&good.replace("500000", "4294967296")).unwrap();
        assert!(w.validate().is_err());
        let mut s = state();
        s.remainders.as_mut().unwrap().insert("eth0".into(), Pair { rx: PPM, tx: 0 });
        assert!(s.validate().is_err());
        let mut s = state();
        s.schema = 1;
        assert!(s.validate().is_err());
        s.remainder = Some(Pair::default());
        assert!(s.validate().is_err());
        assert!(legacy_state(Pair { rx: PPM, tx: 0 }).validate().is_err());
        let mut invalid = serde_json::to_value(legacy_state(Pair::default())).unwrap();
        invalid["remainders"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<State>(invalid).is_err());
        let tmp = Temp::new();
        let mut config = tmp.config();
        config.checkpoint_secs = 1;
        assert!(config.validate(&Ifaces::default()).is_err());
        assert!(serde_json::from_str::<Config>(r#"{"state_file":"/tmp/s","typo":true}"#).is_err());
        for name in [".", "..", "../eth0", "a/b", "*", "-eth0", "eth0:1", "this-name-is-too-long"] {
            assert!(validate_name(name).is_err());
        }
    }

    #[test]
    fn filter_reuses_native_topology_exclusion_and_reports_missing_names() {
        let ifaces = Ifaces::parse("eth0,relay,-relay,missing").unwrap();
        assert!(ifaces.counts(Path::new("/nonexistent"), "eth0"));
        assert!(!ifaces.counts(Path::new("/nonexistent"), "relay"));
        assert!(!ifaces.counts(Path::new("/nonexistent"), "eth1"));
        assert_eq!(ifaces.missing(["eth0"].into_iter()), ["missing"]);
        assert!(!Ifaces::default().counts(Path::new("/nonexistent"), "wg0"));
        assert!(!Ifaces::default().counts(Path::new("/nonexistent"), "vlan0"));
        let dev =
            "Inter-| Receive | Transmit\n face |bytes |bytes\n eth0: 100 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0\n";
        assert_eq!(counters(dev).unwrap()["eth0"], (100, 200));
        assert!(counters(&dev.replace("200", "oops")).is_err());
        assert!(counters(&dev.replace(" 200 0", "")).is_err());
        assert!(counters("").is_err());
    }

    #[test]
    fn collection_errors_clear_baselines_without_writing_zero() {
        let tmp = Temp::new();
        let mut l = tmp.ledger();
        let t = l.last_save;
        l.observe(&sample(&[("eth0", 100, 100, identity_weights())]), t).unwrap();
        // Name is absent on every Linux test runner. Strict mode refuses to
        // collect even when other real interfaces exist.
        assert!(l.collect(&Ifaces::parse("missing-test0").unwrap()).is_err());
        assert!(l.pending.links.is_empty());
        assert_eq!(read_state(&l.config.state_file).unwrap().raw, state().raw);
        assert_eq!(
            l.observe(&sample(&[("eth0", 999_999, 999_999, identity_weights())]), t + Duration::from_secs(5))
                .unwrap()
                .total,
            state().billing
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(start_paused = true)]
    async fn sampling_checkpoints_raw_loopback_traffic_without_a_hub() {
        let tmp = Temp::new();
        let mut config = tmp.config();
        config.report = Report::Raw;
        config.weights.insert(
            "lo".into(),
            Weights { rx_to_in_ppm: 0, rx_to_out_ppm: 0, tx_to_in_ppm: 0, tx_to_out_ppm: 0 },
        );
        save(&config.state_file, &State::new(state().seed, Report::Raw).unwrap()).unwrap();
        let ledger = Ledger::open(config).unwrap();
        let mut traffic = ledger.start(Ifaces::parse("lo").unwrap(), Duration::from_secs(1));
        traffic.changed().await.unwrap();
        assert_eq!(traffic.borrow().as_ref().unwrap().total, state().raw);

        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(&[42; 256], receiver.local_addr().unwrap()).unwrap();
        tokio::time::advance(Duration::from_secs(5)).await;
        traffic.changed().await.unwrap();
        let reading = traffic.borrow();
        let reading = reading.as_ref().unwrap();
        let saved = read_state(&tmp.config().state_file).unwrap();
        assert_eq!(reading.total, saved.raw);
        assert!(reading.rate.rx >= 51 && reading.rate.tx >= 51);
        assert_eq!(saved.billing, state().billing);
        assert_eq!(saved.checkpoints, 1);
    }

    #[test]
    fn explicit_init_never_overwrites_existing_state_or_creates_identity() {
        let tmp = Temp::new();
        let config = tmp.config();
        let seed = tmp.0.join("seed.json");
        fs::write(&seed, serde_json::to_vec(&state().seed).unwrap()).unwrap();
        initialize(&config, seed.to_str().unwrap()).unwrap();
        let s = read_state(&config.state_file).unwrap();
        assert_eq!(s.seed.boot_id, state().seed.boot_id);
        assert!(s.kernel_boot_id.is_empty() && s.links.is_empty());
        assert!(initialize(&config, seed.to_str().unwrap()).is_err());
        assert_eq!(s.raw, read_state(&config.state_file).unwrap().raw);
    }
}
