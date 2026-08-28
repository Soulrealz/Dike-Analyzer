# corpus/notes

This directory holds derived notes that are our own original work: summaries,
write-ups, and analysis produced while building or curating the corpus,
rather than content fetched from a third party.

It is referenced by the `notes-local` entry in `corpus/sources.toml`
(`kind = "local"`, `url = "corpus/notes"`), so `dike corpus fetch` reads
whatever is placed here directly, with no network access involved.

Unlike fetched sources under `corpus/cache/` — which are gitignored because
their licensing does not permit redistribution (see spec §7 licensing) —
files in this directory are original work and are safe, and expected, to be
committed to version control.

Add `.md` (or plain text) files here as notes accumulate.
