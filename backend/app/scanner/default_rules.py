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
# Specific token/key rules (R001-R005) have the highest priority.
# Assignment rules (R006-R008) are next.
# PRODUCTION_ENV_WITH_SECRET (R011) has the lowest content priority --
# it is also file-level suppressed if any specific rule found something.
# File-type rules (R009) don't participate in line-level dedup.
RULE_PRIORITY_MAP: dict[str, int] = {
    "R001_GITHUB_TOKEN": 1,
    "R002_AWS_ACCESS_KEY": 2,
    "R003_AWS_SECRET_KEY": 3,
    "R004_GOOGLE_API_KEY": 4,
    "R005_PRIVATE_KEY": 5,
    "R006_PASSWORD_ASSIGNMENT": 6,
    "R007_GENERIC_TOKEN_ASSIGNMENT": 7,
    "R008_CONNECTION_STRING": 8,
    "R011_PRODUCTION_ENV_WITH_SECRET": 11,
    "R009_ENV_FILE_PRESENT": 100,  # file-type, doesn't participate in line dedup
}

# Rule IDs considered "specific" -- if any of these produce a finding in a file,
# PRODUCTION_ENV_WITH_SECRET (R011) findings for that file are suppressed.
SPECIFIC_RULE_IDS: frozenset[str] = frozenset({
    "R001_GITHUB_TOKEN",
    "R002_AWS_ACCESS_KEY",
    "R003_AWS_SECRET_KEY",
    "R004_GOOGLE_API_KEY",
    "R005_PRIVATE_KEY",
    "R006_PASSWORD_ASSIGNMENT",
    "R007_GENERIC_TOKEN_ASSIGNMENT",
    "R008_CONNECTION_STRING",
})
