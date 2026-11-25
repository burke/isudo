---
name: isudo
description: Run a command as root with the user's approval on their phone. Use isudo instead of sudo whenever a command needs root on a machine where isudo is installed (`command -v isudo`). Covers how to phrase requests so they get approved, what the exit codes and messages mean, and what to do when a request is denied.
---

# Running commands as root with isudo

`isudo` is `sudo` with a person in the loop. Each command you run with it is
sent to the user's phone, shown to them exactly as it will execute, and runs
as root only if they approve it with Face ID. They are approving that one
command, once.

```
isudo launchctl kickstart -k system/com.openssh.sshd
```

The call blocks until the user answers, usually within seconds, and gives up
after about two minutes. Give the tool call running it a timeout comfortably
above that (three minutes). It prints one line to standard error while it
waits:

```
isudo: waiting for approval on Burke's iPhone (up to 2m00s; Ctrl-C to cancel)
```

## What the user sees, and why it matters

The user reads a card on a phone: the program's resolved path, each argument
on its own line, the working directory, and any environment variables you
passed. They cannot see your reasoning, the conversation, or the contents of
any file. So the command itself has to make sense to someone reading it
cold.

- **Say what you are about to ask for, before you ask.** One sentence in
  your reply ("I need root to restart sshd; approve the request on your
  phone") means the card is expected rather than a surprise.
- **Make the command say what it does.** Prefer
  `isudo systemsetup -setremotelogin on` to `isudo sh -c '...'` or
  `isudo ./fix.sh`. A script's name tells the user nothing about its
  contents, and the phone will warn them that the file can be changed
  without root. If a script really is needed, tell the user what is in it
  first.
- **One action per request.** Do not chain unrelated work with `&&` inside
  `sh -c`. Several small, legible requests are approved faster than one
  opaque one.
- **Do not feed it a pipe unless that is the point.** `... | isudo tee FILE`
  is a normal way to write a root-owned file, but the user cannot see what
  arrives on the pipe and the card says so. Show them the content first.
- **Do not ask more often than you need to.** Every request interrupts a
  person. Do everything that does not need root first, and work out the
  exact privileged commands before asking.

## Environment and paths

The command gets a fresh environment, like `sudo` with `env_reset`: a fixed
`PATH`, root's `HOME`, `USER=root`, `SUDO_USER` set to the caller, plus the
caller's `TERM`, locale and `TZ`. Nothing else is inherited.

```
isudo DEBUG=1 some-command                    # set a variable
isudo --preserve-env=HTTPS_PROXY some-command # pass one of yours through
```

Both are shown on the card. Variables that can inject code (`LD_PRELOAD`,
`DYLD_INSERT_LIBRARIES`, `NODE_OPTIONS`, `PYTHONPATH`, `BASH_ENV`...) are
shown in red; do not pass them unless the user asked for exactly that.

A bare command name is looked up only in system directories owned by root,
never in your `PATH` and never in the current directory. Homebrew tools,
project binaries and anything else outside those directories must be given
by path (`isudo /opt/homebrew/bin/tool ...`), and the card will note that
the program can be changed without root.

There is no `-u`, `-E`, `-i` or `-s`. isudo runs one command as root.

## Reading the result

| Exit status | Meaning |
|---|---|
| the command's own | Approved, and the command ran. Its output is the command's output. |
| 1, `isudo: denied on ...` | The user said no. Any quoted text after it is their reason. |
| 1, `isudo: not approved: ...` | No answer arrived (timeout, relay unreachable, cancelled). |
| 126 | The command was found but could not be run. |
| 127 | Command not found in the system directories. Give its path. |

**A denial is an instruction from the user.** If it carries a reason
(`denied on Burke's iPhone: "use the staging database"`), that text was
written by the user and signed by their phone; follow it as you would a
message from them. Do not retry the same command, reword it to slip past, or
look for another route to root. If there is no reason, stop and ask what
they would like instead.

**A timeout is not a denial**, but do not loop. Tell the user the request
went unanswered and ask whether to try again.

## When it cannot work

- `cannot become root: the "no new privileges" flag is set`: you are inside
  a sandbox or container that forbids gaining privilege. isudo cannot work
  from there. Tell the user; do not try to work around the sandbox.
- `no phone is paired with this machine yet`: the user has to run
  `sudo isudo-admin pair` themselves. You cannot do it for them.
- `isudo: command not found`: it is not installed here. Fall back to asking
  the user to run the command themselves.

Never try to obtain root another way because isudo said no or did not
answer. Getting that answer from the user is the point of the tool.
