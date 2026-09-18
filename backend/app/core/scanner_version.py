"""Scanner version identity used in task deduplication keys.

Bump whenever scan rules, assessment policy, or repair policy change in a
way that should invalidate previously completed results for the same commit.
"""

# Scan schema + assessment policy + repair policy + rules identity.
SCANNER_VERSION = "scanner-v1|p0-6-v1|p0-7-v1|schema-v2"
