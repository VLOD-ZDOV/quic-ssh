//! `qsh completions SHELL`: scripts that complete qsh's commands and host
//! names. The scripts ask `qsh completions --hosts` for the names each time,
//! so hosts added later (in a config, `qsh ui` or known_hosts) complete too.

use std::path::Path;

/// The tools, as the scripts complete them in the first position.
const TOOLS: &str = "cp pair keygen speed ui multi doctor update forget completions";

const BASH: &str = r#"# qsh completion for bash: source <(qsh completions bash)
_qsh() {
    local cur=${COMP_WORDS[COMP_CWORD]} first=${COMP_WORDS[1]}
    local hosts
    hosts=$(qsh completions --hosts 2>/dev/null)
    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=($(compgen -W "@TOOLS@ $hosts" -- "$cur"))
        return
    fi
    case $first in
        speed|doctor|forget|pair) [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=($(compgen -W "$hosts" -- "$cur")) ;;
        completions) COMPREPLY=($(compgen -W "bash zsh fish" -- "$cur")) ;;
        cp) COMPREPLY=($(compgen -f -- "$cur") $(compgen -W "$(printf '%s: ' $hosts)" -- "$cur")) ;;
        *) COMPREPLY=($(compgen -f -- "$cur")) ;;
    esac
}
complete -F _qsh qsh
"#;

const ZSH: &str = r#"# qsh completion for zsh: source <(qsh completions zsh)
_qsh() {
    local -a tools hosts
    tools=(@TOOLS@)
    hosts=(${(f)"$(qsh completions --hosts 2>/dev/null)"})
    if (( CURRENT == 2 )); then
        compadd -a tools hosts
        return
    fi
    case $words[2] in
        speed|doctor|forget|pair) (( CURRENT == 3 )) && compadd -a hosts ;;
        completions) compadd bash zsh fish ;;
        cp) _files; compadd -S '' -- ${^hosts}: ;;
        *) _files ;;
    esac
}
compdef _qsh qsh
"#;

const FISH: &str = r#"# qsh completion for fish: qsh completions fish > ~/.config/fish/completions/qsh.fish
complete -c qsh -f
complete -c qsh -n __fish_use_subcommand -a '@TOOLS@' -d command
complete -c qsh -n __fish_use_subcommand -a '(qsh completions --hosts 2>/dev/null)' -d host
complete -c qsh -n '__fish_seen_subcommand_from speed doctor forget pair' -a '(qsh completions --hosts 2>/dev/null)' -d host
complete -c qsh -n '__fish_seen_subcommand_from completions' -a 'bash zsh fish'
complete -c qsh -n '__fish_seen_subcommand_from cp' -F
complete -c qsh -n '__fish_seen_subcommand_from cp' -a '(qsh completions --hosts 2>/dev/null | string replace -r \'$\' :)' -d host
"#;

/// The script for `shell`.
pub fn script(shell: &str) -> Option<String> {
    let text = match shell {
        "bash" => BASH,
        "zsh" => ZSH,
        "fish" => FISH,
        _ => return None,
    };
    Some(text.replace("@TOOLS@", TOOLS))
}

/// Host names to complete: aliases from the configs and `qsh ui`, then the
/// hosts in qsh's known_hosts (`[host]:port` as `host:port`).
pub fn hosts(home: &Path) -> Vec<String> {
    let mut out = super::config::host_aliases(home);
    for id in super::known_host_ids() {
        let dest = match id.strip_prefix('[').and_then(|r| r.split_once("]:")) {
            Some((h, p)) if !h.contains(':') => format!("{h}:{p}"),
            Some(_) => continue,
            None => id,
        };
        if !out.contains(&dest) {
            out.push(dest);
        }
    }
    // Names a shell would take apart, or that look like options.
    out.retain(|h| !h.is_empty() && !h.starts_with('-') && !h.contains(|c: char| c.is_whitespace() || "'\"`$\\;&|<>(){}*?".contains(c)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripts_name_every_tool() {
        for shell in ["bash", "zsh", "fish"] {
            let s = script(shell).unwrap();
            assert!(s.contains("forget completions") && !s.contains("@TOOLS@"), "{shell}");
        }
        assert!(script("tcsh").is_none());
    }
}
