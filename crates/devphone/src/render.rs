//! Drawing an approval card in a terminal.
//!
//! The rules are the ones the iOS app follows: one argument per line so
//! boundaries are visible, nothing truncated, every invisible or control
//! character escaped, and anything that weakens what the argument list tells
//! you called out.

use isudo_proto::envrisk::is_risky;
use isudo_proto::request::{EnvOrigin, Request, StdinKind, FLAG_EXE_WRITABLE};
use isudo_proto::text::escape;

fn line(out: &mut String, text: &str) {
    out.push_str("  | ");
    out.push_str(text);
    out.push('\n');
}

/// The card as text. `seconds_left` is how long the host will keep waiting.
pub(crate) fn card(request: &Request, seconds_left: u64) -> String {
    let mut out = String::new();

    let user = if request.user.is_empty() { "unknown user".to_owned() } else { escape(&request.user) };
    out.push_str(
        &[
            "  .- ",
            &escape(&request.host),
            " : ",
            &user,
            " (uid ",
            &request.uid.to_string(),
            ") wants to run as root\n",
        ]
        .concat(),
    );
    line(&mut out, &escape(&request.exe));
    for arg in &request.argv {
        line(&mut out, &["    ", &escape(arg)].concat());
    }
    line(&mut out, &["in ", &escape(&request.cwd)].concat());

    if request.flags & FLAG_EXE_WRITABLE != 0 {
        line(&mut out, "! this program can be changed without root, so the arguments say little");
    }
    match request.stdin {
        StdinKind::Terminal | StdinKind::Null => {}
        StdinKind::Pipe | StdinKind::File | StdinKind::Socket | StdinKind::Other => {
            line(&mut out, "! reads input that is not shown here (a pipe or file)");
        }
    }
    for var in &request.env {
        let shown = [escape(&var.name), "=".to_owned(), escape(&var.value)].concat();
        match var.origin {
            EnvOrigin::Explicit if is_risky(&var.name) => {
                line(&mut out, &["! sets ", &shown, "  (can make the program run other code)"].concat());
            }
            EnvOrigin::Explicit => line(&mut out, &["sets ", &shown].concat()),
            EnvOrigin::Default | EnvOrigin::Constructed => {}
        }
    }
    if !request.ancestry.is_empty() {
        let chain: Vec<String> = request.ancestry.iter().map(|a| escape(&a.name)).collect();
        line(&mut out, &["asked by (unverified): ", &chain.join(" < ")].concat());
    }
    out.push_str(&["  '- expires in ", &seconds_left.to_string(), "s\n"].concat());
    out
}

#[cfg(test)]
mod tests {
    use isudo_proto::request::{Ancestor, EnvVar};

    use super::*;

    fn request() -> Request {
        Request {
            nonce: [1; 32],
            pairing_id: [2; 16],
            issued_at: 1000,
            ttl_secs: 120,
            uid: 501,
            gid: 20,
            user: b"burke".to_vec(),
            host: b"burke-mbp".to_vec(),
            cwd: b"/Users/burke/app".to_vec(),
            exe: b"/usr/bin/tee".to_vec(),
            flags: 0,
            stdin: StdinKind::Terminal,
            argv: vec![b"tee".to_vec(), b"/etc/hosts".to_vec()],
            env: vec![EnvVar { origin: EnvOrigin::Default, name: b"TERM".to_vec(), value: b"xterm".to_vec() }],
            ancestry: Vec::new(),
        }
    }

    fn rendered(request: &Request) -> String {
        card(request, 110)
    }

    #[test]
    fn a_plain_request_has_no_warnings() {
        let text = rendered(&request());
        assert_eq!(
            text,
            "  .- burke-mbp : burke (uid 501) wants to run as root\n\
             \x20 | /usr/bin/tee\n\
             \x20 |     tee\n\
             \x20 |     /etc/hosts\n\
             \x20 | in /Users/burke/app\n\
             \x20 '- expires in 110s\n"
        );
    }

    #[test]
    fn everything_that_weakens_the_argument_list_is_called_out() {
        let mut request = request();
        request.flags = FLAG_EXE_WRITABLE;
        request.stdin = StdinKind::Pipe;
        request.env.push(EnvVar { origin: EnvOrigin::Explicit, name: b"DEBUG".to_vec(), value: b"1".to_vec() });
        request.env.push(EnvVar {
            origin: EnvOrigin::Explicit,
            name: b"LD_PRELOAD".to_vec(),
            value: b"/tmp/x.so".to_vec(),
        });
        request.ancestry =
            vec![Ancestor { pid: 2, name: b"zsh".to_vec() }, Ancestor { pid: 1, name: b"claude".to_vec() }];
        let text = rendered(&request);
        assert!(text.contains("! this program can be changed without root"));
        assert!(text.contains("! reads input that is not shown here"));
        assert!(text.contains("  | sets DEBUG=1\n"));
        assert!(text.contains("! sets LD_PRELOAD=/tmp/x.so  (can make the program run other code)"));
        assert!(text.contains("asked by (unverified): zsh < claude"));
        assert!(!text.contains("TERM"), "default variables are not worth the reader's attention");
    }

    #[test]
    fn nothing_can_hide_in_an_argument() {
        let mut request = request();
        request.argv = vec![
            b"sh".to_vec(),
            b"-c".to_vec(),
            "echo ok\n\u{202e}rm -rf /\x1b[2K\r".as_bytes().to_vec(),
            b"\xff".to_vec(),
        ];
        let text = rendered(&request);
        assert!(text.contains("  |     echo ok\\n\\u{202e}rm -rf /\\u{1b}[2K\\r\n"));
        assert!(text.contains("  |     \\xff\n"));
        assert!(!text.contains('\u{1b}') && !text.contains('\u{202e}'));
    }
}
