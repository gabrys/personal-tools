# Shell commands in aap-ui

The approval parser supports a deliberately limited shell syntax. It never
evaluates commands or expands variables. The original command is preserved for
execution; parsed parts are used only for review and rule matching.

Supported syntax:

- Simple commands, single/double quotes, and escaped characters.
- Chains separated by `&&`, `||`, `;`, or newlines.
- Pipelines with `|`. Each command needs approval before the whole call proceeds.
- Command-local assignments such as `CI=1 cmd`. Rules must include assignments;
  a rule for `cmd` does not cover commands with a modified environment.
- `2>&1`, `1>&2`, and output redirections to `/dev/null`. These remain visible
  in the original command but are ignored when matching command prefixes.
- Inline `python3 -c '…'` scripts, including command-local assignments. Scripts with more than 3 lines or more than 200 characters are reviewed
  automatically and have a single Accept button for one-time approval. They appear
  in the UI when review finishes or 10 seconds after receipt, whichever comes first. Accepting
  them never creates a rule or approves another request for the same script.
  Shorter scripts are ordinary commands and use the usual approval rules.

File redirections such as `> output.txt`, `>> output.txt`, and `< input.txt`
are rejected with guidance to use file operations checked by path-based rules.

Other syntax is rejected before approval rules are consulted: loops,
conditionals, functions, grouping, background execution, command/process
substitution, variable/arithmetic expansion, globbing, brace/tilde expansion,
standalone assignments, heredocs (`<<EOF`, `<<END`, `<<-EOF`), here-strings,
comments, and escaped newlines. Invalid syntax is also rejected.

The response to unsupported syntax is:

> This command contains unsupported shell constructs. Rewrite it as a single
> python3 -c '…' command, or run several commands separately if that makes
> sense for the task.

Operators and the full original command remain available in the approval UI.
Approvals never turn the parts into independent executions or change the shell's
execution order and success conditions.
