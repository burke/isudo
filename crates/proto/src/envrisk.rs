//! Environment variables that can make a program run code of the caller's
//! choosing. They are never passed by default; if the caller asks for one
//! explicitly, the approver sees it called out.
//!
//! Sources: sudo's `initial_badenv_table` (plugins/sudoers/env.c), glibc's
//! secure-execution list (sysdeps/generic/unsecvars.h), and a few interpreter
//! and tool variables neither list covers. The iOS app carries the same list.

/// Exact names.
const EXACT: &[&str] = &[
    // sudo: shells
    "IFS", "CDPATH", "ENV", "BASH_ENV", "PS4", "GLOBIGNORE", "BASHOPTS", "SHELLOPTS",
    "FPATH", "NULLCMD", "READNULLCMD", "ZDOTDIR", "TMPPREFIX",
    // sudo: resolver, locale, terminal databases
    "LOCALDOMAIN", "RES_OPTIONS", "HOSTALIASES", "NLSPATH", "PATH_LOCALE",
    "TERMINFO", "TERMINFO_DIRS", "TERMPATH", "TERMCAP",
    // sudo: language runtimes
    "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH",
    "PERLIO_DEBUG", "PERLLIB", "PERL5LIB", "PERL5OPT", "PERL5DB",
    "PYTHONHOME", "PYTHONPATH", "PYTHONINSPECT", "PYTHONUSERBASE", "PYTHONSTARTUP",
    "RUBYLIB", "RUBYOPT", "NODE_OPTIONS", "NODE_PATH",
    "GIT_SSH_COMMAND", "GIT_SSH", "GIT_EXEC_PATH", "GIT_ASKPASS", "GIT_EXTERNAL_DIFF",
    "GCONV_PATH",
    // glibc secure-execution list (entries not already covered by LD_*)
    "GETCONF_DIR", "GLIBC_TUNABLES", "LOCPATH", "MALLOC_TRACE", "NIS_PATH",
    "RESOLV_HOST_CONF", "TMPDIR", "TZDIR",
    // commonly honoured by root-run tools
    "PATH", "HOME", "SHELL", "EDITOR", "VISUAL", "SUDO_EDITOR", "PAGER", "MANPAGER",
    "LESSOPEN", "LESSCLOSE", "SSH_ASKPASS", "SUDO_ASKPASS", "MAIL_CONFIG",
    "LUA_PATH", "LUA_CPATH", "LUA_INIT", "PYTHONBREAKPOINT", "PYTHONWARNINGS",
    "RUSTC_WRAPPER", "CARGO_HOME", "GOFLAGS", "DOCKER_HOST", "KUBECONFIG",
    "CURL_HOME", "WGETRC", "OPENSSL_CONF", "SSL_CERT_FILE", "SSL_CERT_DIR",
    "NIX_PATH", "NIX_CONF_DIR", "XDG_CONFIG_HOME", "XDG_CONFIG_DIRS", "XDG_DATA_DIRS",
];

/// Name prefixes.
const PREFIXES: &[&str] = &[
    "LD_", "DYLD_", "_RLD", "LDR_", "KRB5_CONFIG", "GIT_CONFIG", "BASH_FUNC_",
    "MALLOC_", "NPM_CONFIG_", "PIP_", "BUNDLE_", "GEM_", "RUBY", "PERL5", "NODE_",
    "PYTHON",
];

/// True if handing this variable to a root process deserves a warning.
#[must_use]
pub fn is_risky(name: &[u8]) -> bool {
    let Ok(name) = std::str::from_utf8(name) else {
        return true;
    };
    EXACT.contains(&name) || PREFIXES.iter().any(|p| name.starts_with(p))
}

/// True if the value is an exported shell function, which bash imports and
/// which has no legitimate reason to cross into a root process.
#[must_use]
pub fn is_shell_function(value: &[u8]) -> bool {
    value.starts_with(b"()")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_the_usual_suspects() {
        for name in [
            "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "BASH_ENV", "PYTHONPATH", "NODE_OPTIONS",
            "GIT_SSH_COMMAND", "GIT_CONFIG_GLOBAL", "PERL5LIB", "PATH", "BASH_FUNC_x%%",
        ] {
            assert!(is_risky(name.as_bytes()), "{name} should be flagged");
        }
    }

    #[test]
    fn leaves_ordinary_names_alone() {
        for name in ["TERM", "LANG", "LC_ALL", "TZ", "DEBUG", "MY_APP_TOKEN", "CI", "NO_COLOR"] {
            assert!(!is_risky(name.as_bytes()), "{name} should not be flagged");
        }
    }

    #[test]
    fn non_utf8_names_are_risky() {
        assert!(is_risky(&[0xff, 0xfe]));
    }
}
