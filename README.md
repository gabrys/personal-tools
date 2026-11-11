# personal-tools

## sucker

`sucker ps` and `sucker compose ...` start a persistent broker in a detached
tmux session automatically. Enter the Docker PIN (the `sucker` account password)
once in Zenity; approve each command in a separate dialog.
Docker runs as the `sucker` user. The tool uses Python's standard library only.
To install, run `./sucker broker setup`, then link `~/.local/bin/sucker` to the
script in this repository.
`sucker askpass` opens the masked Docker PIN prompt and writes the entered PIN
to stdout for programs that use the askpass protocol.

## prefix-cleanup

Interactively shorten allowed Codex prefixes to two elements (a command and one
argument), for example `git add abc` and `git add xyz` → `git add`.
Requires Python 3.9+ and uses the standard library only.

```bash
./prefix-cleanup /path/to/default.rules
```

The rules file path is required.

The tool displays one single-line prompt for each proposal, such as
`Prefix "git add ..."? [A]llow [p]rompt [d]eny [s]kip [v]iew [l]onger` (the
capital letter marks the default). Answer `a` (or Enter) to add the prefix with
`decision="allow"`, `p` for `decision="prompt"` (always ask), `d` for
`decision="forbidden"`, or `s` to skip it. `v` shows the rules that the prefix
would shorten, as shell commands, and asks again. `l` replaces the proposal
with longer prefixes (one more element each), for example `python3 -m ...` →
`python3 -m py_compile ...`; other answers repeat the question.
Prompt and deny rules do not make longer allow rules redundant, and prefixes
that already have a rule are not proposed again. Then `Add N rule(s)? [y/N]`
confirms adding the selected rules (Enter declines).
A separate prompt, `Remove N rule(s) covered by shorter prefixes? [y/N]`,
offers to remove rules covered by existing or newly added prefixes (Enter keeps
them). Batch prompts appear only when N > 0.

Shortening a rule grants permission for every argument sequence after the
selected prefix. Adding and removing rules require separate confirmations.
Comments are preserved; rules with extra attributes are skipped. Before saving,
the tool removes blank lines after confirmed rule cleanup and creates a `.bak-*`
copy beside the file before saving. Ctrl+C or end-of-input cancels the session
without saving.

Run tests with `python3 -m unittest discover -s tests -v`.
