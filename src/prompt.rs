//! Asking the user: on the terminal, or through `SSH_ASKPASS` like OpenSSH
//! (graphical prompts, or automation with `SSH_ASKPASS_REQUIRE=force`).

use std::io::{BufRead, Write};

use anyhow::{bail, Context, Result};

/// Whether to use the askpass program, following OpenSSH's rules.
fn use_askpass() -> Option<String> {
    let program = std::env::var("SSH_ASKPASS").ok().filter(|p| !p.is_empty())?;
    let require = std::env::var("SSH_ASKPASS_REQUIRE").unwrap_or_default();
    let graphical = std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some();
    let no_tty = std::fs::OpenOptions::new().read(true).open("/dev/tty").is_err();
    match require.as_str() {
        "never" => None,
        "force" | "prefer" => Some(program),
        _ if no_tty && graphical => Some(program),
        _ => None,
    }
}

fn askpass(program: &str, prompt: &str) -> Result<String> {
    let out = std::process::Command::new(program)
        .arg(prompt)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .output()
        .with_context(|| format!("cannot run askpass program {program}"))?;
    if !out.status.success() {
        bail!("askpass program {program} was cancelled");
    }
    let text = String::from_utf8(out.stdout).context("askpass output is not UTF-8")?;
    Ok(text.lines().next().unwrap_or_default().to_string())
}

/// Asks for a secret (passphrase, one-time code) without echoing it.
pub fn secret(prompt: &str) -> Result<String> {
    match use_askpass() {
        Some(program) => askpass(&program, prompt),
        None => rpassword::prompt_password(prompt).context("cannot read from the terminal"),
    }
}

/// Asks a question whose answer may be shown while typed.
pub fn line(prompt: &str) -> Result<String> {
    if let Some(program) = use_askpass() {
        return askpass(&program, prompt);
    }
    let tty = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").context("no terminal to answer on")?;
    write!(&tty, "{prompt}")?;
    (&tty).flush()?;
    let mut answer = String::new();
    std::io::BufReader::new(&tty).read_line(&mut answer)?;
    Ok(answer.trim_end_matches(['\r', '\n']).to_string())
}
