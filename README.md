# personal-tools

## sucker

`sucker ps` and `sucker compose ...` start a persistent broker in a detached
tmux session automatically. Enter the Docker PIN (the `sucker` account password)
once in Zenity; approve each command in a separate dialog.
Docker runs as the `sucker` user. The tool uses Python's standard library only.
To install, run `./sucker broker setup`, then link `~/.local/bin/sucker` to the
script in this repository.

## prefix-cleanup

Interactively shorten allowed Codex prefixes to two elements (a command and one
argument), for example `git add abc` and `git add xyz` → `git add`.
Requires Python 3.9+ and uses the standard library only.

```bash
./prefix-cleanup /path/to/default.rules
```

The rules file path is required.

The tool displays one single-line prompt for each proposal, such as
`Allow "git add ..."? [Y/n]`. Press Enter or `y`/`yes` to accept a prefix, or
`n` to skip it. Then `Add N rule(s)? [y/N]` confirms adding the selected rules
(Enter declines). A separate prompt, `Remove N rule(s) covered by shorter
prefixes? [y/N]`, offers to remove rules covered by existing or newly added
prefixes (Enter keeps them). Batch prompts appear only when N > 0.

Shortening a rule grants permission for every argument sequence after the
selected prefix. Adding and removing rules require separate confirmations.
Comments are preserved; rules with extra attributes are skipped. Before saving,
the tool removes blank lines after confirmed rule cleanup and creates a `.bak-*`
copy beside the file before saving. Ctrl+C or end-of-input cancels the session
without saving.

Run tests with `python3 -m unittest discover -s tests -v`.
