//! Host groups (`~/.config/qsh/groups`), for `qsh multi -g NAME` and the
//! menu. A TOML file of `name = ["host", ...]`; editable by hand or in
//! `qsh ui`. The hosts are names as typed for `qsh` (aliases or `user@host`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

pub type Groups = BTreeMap<String, Vec<String>>;

pub fn path(home: &Path) -> PathBuf {
    crate::keys::qsh_dir(home).join("groups")
}

/// Group names: one word, so they can be typed on the command line.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.chars().all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

pub fn load(home: &Path) -> Result<Groups> {
    let file = path(home);
    match std::fs::read_to_string(&file) {
        Ok(text) => toml::from_str(&text).with_context(|| format!("invalid {}", file.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Groups::new()),
        Err(e) => Err(e).with_context(|| format!("cannot read {}", file.display())),
    }
}

pub fn save(home: &Path, groups: &Groups) -> Result<()> {
    for name in groups.keys() {
        if !valid_name(name) {
            bail!("bad group name {name:?}");
        }
    }
    let file = path(home);
    crate::keys::create_private_dir(file.parent().context("bad path")?)?;
    let groups: Groups = groups.iter().filter(|(_, hosts)| !hosts.is_empty()).map(|(k, v)| (k.clone(), v.clone())).collect();
    let text = format!("# Host groups for `qsh multi -g NAME` and `qsh ui` (g sets a host's groups).\n{}", toml::to_string(&groups)?);
    let tmp = file.with_extension("new");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, &file)?;
    Ok(())
}

/// The groups `host` is in.
pub fn of(groups: &Groups, host: &str) -> Vec<String> {
    groups.iter().filter(|(_, hosts)| hosts.iter().any(|h| h == host)).map(|(g, _)| g.clone()).collect()
}

/// Puts `host` in exactly the groups `names`.
pub fn set(groups: &mut Groups, host: &str, names: &[String]) {
    for (name, hosts) in groups.iter_mut() {
        let wanted = names.contains(name);
        let there = hosts.iter().any(|h| h == host);
        if there && !wanted {
            hosts.retain(|h| h != host);
        }
    }
    for name in names {
        let hosts = groups.entry(name.clone()).or_default();
        if !hosts.iter().any(|h| h == host) {
            hosts.push(host.to_string());
        }
    }
    groups.retain(|_, hosts| !hosts.is_empty());
}

/// A host's old name became `new` (renamed in the menu).
pub fn rename(groups: &mut Groups, old: &str, new: &str) {
    for hosts in groups.values_mut() {
        for h in hosts.iter_mut().filter(|h| *h == old) {
            *h = new.to_string();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_file() {
        let home = tempfile::tempdir().unwrap();
        let mut g = load(home.path()).unwrap();
        assert!(g.is_empty());
        set(&mut g, "web1", &["web".into(), "prod".into()]);
        set(&mut g, "web2", &["web".into()]);
        set(&mut g, "db", &["prod".into()]);
        assert_eq!(of(&g, "web1"), ["prod", "web"]);
        set(&mut g, "web1", &["web".into()]);
        assert_eq!(g["prod"], ["db"]);
        rename(&mut g, "web2", "web-2");
        save(home.path(), &g).unwrap();
        let back = load(home.path()).unwrap();
        assert_eq!(back, g);
        assert_eq!(back["web"], ["web1", "web-2"]);
        set(&mut g, "db", &[]);
        assert!(!g.contains_key("prod"), "empty groups go away");
        assert!(!valid_name("two words") && !valid_name("") && valid_name("prod-eu_1"));
        std::fs::write(path(home.path()), "web = 5").unwrap();
        assert!(load(home.path()).is_err());
    }
}
