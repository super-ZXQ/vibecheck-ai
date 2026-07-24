"""Default rule registry and priority map.

This module is the single source of truth for:
- DEFAULT_RULES: ordered list of rule instances used by the scanner.
- RULE_PRIORITY_MAP: rule_id -> priority (lower number = higher priority).

Import structure (no circular imports):
- imports from: rules
- imported by:  sensitive
"""

from app.scanner.rules import (
    AWSAccessKeyRule,
    AWSSecretKeyRule,
    ConnectionStringRule,
    EnvExampleFileRule,
    EnvFilePresentRule,
    GenericTokenAssignmentRule,
    GitHubTokenRule,
    GoogleAPIKeyRule,
    PasswordAssignmentRule,
    PrivateKeyRule,
    ProductionEnvWithSecretRule,
)

# Ordered list of default rules.
# Order matters only for readability; actual priority is determined by RULE_PRIORITY_MAP.
DEFAULT_RULES: list = [
    GitHubTokenRule(),               # R001
    AWSAccessKeyRule(),              # R002
    AWSSecretKeyRule(),              # R003
    GoogleAPIKeyRule(),              # R004
    PrivateKeyRule(),                # R005
    PasswordAssignmentRule(),        # R006
    GenericTokenAssignmentRule(),    # R007
    ConnectionStringRule(),          # R008
    EnvFilePresentRule(),            # R009
    EnvExampleFileRule(),            # R010
    ProductionEnvWithSecretRule(),   # R011
]

# Priority map: lower number = higher priority.
# When two content findings overlap on the same line, the higher-priority
# (lower number) finding is kept and the other is dropped.
#
# Explicit format rules (R001-R005) have the highest priority.
# R011 (ProductionEnvWithSecret) is next — higher than generic heuristics
# (R006-R008) so that R011's blocking signal is not dropped by non-blocking
# generic matches on the same line.
# Generic assignment rules (R006-R008) have the lowest content priority.
# File-type rules (R009) don't participate in line-level dedup.
RULE_PRIORITY_MAP: dict[str, int] = {
    "R001_GITHUB_TOKEN": 1,
    "R002_AWS_ACCESS_KEY": 2,
    "R003_AWS_SECRET_KEY": 3,
    "R004_GOOGLE_API_KEY": 4,
    "R005_PRIVATE_KEY": 5,
    "R011_PRODUCTION_ENV_WITH_SECRET": 6,
    "R006_PASSWORD_ASSIGNMENT": 7,
    "R007_GENERIC_TOKEN_ASSIGNMENT": 8,
    "R008_CONNECTION_STRING": 9,
    "R009_ENV_FILE_PRESENT": 100,  # file-type, doesn't participate in line dedup
}

# Rule IDs considered "specific" — if any of these produce a finding in a file,
# PRODUCTION_ENV_WITH_SECRET (R011) findings for that file are suppressed.
# Only explicit format rules (R001-R005) suppress R011 — generic heuristics
# (R006-R008) do NOT suppress R011.
SPECIFIC_RULE_IDS: frozenset[str] = frozenset({
    "R001_GITHUB_TOKEN",
    "R002_AWS_ACCESS_KEY",
    "R003_AWS_SECRET_KEY",
    "R004_GOOGLE_API_KEY",
    "R005_PRIVATE_KEY",
})
