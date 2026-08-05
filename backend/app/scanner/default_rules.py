"""Default rule registry and priority map.

This module is the single source of truth for:
- DEFAULT_RULES: ordered list of rule instances used by the scanner.
- RULE_PRIORITY_MAP: rule_id -> priority (lower number = higher priority).

Import structure (no circular imports):
- imports from: rules
- imported by:  sensitive
"""

from app.scanner.basic_security_rules import BasicSecurityRule
from app.scanner.deployability_rules import DeployabilityRule
from app.scanner.documentation_rules import DocumentationConsistencyRule
from app.scanner.incomplete_rules import (
    DebugBreakpointRule,
    ExcessiveDebugOutputRule,
    PlaceholderReturnRule,
    TodoCommentRule,
    UnimplementedCodeRule,
)
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
    TodoCommentRule(),               # I001
    UnimplementedCodeRule(),         # I002
    PlaceholderReturnRule(),         # I003
    DebugBreakpointRule(),           # I004
    ExcessiveDebugOutputRule(),      # I005
    DeployabilityRule(),             # D001-D010 repository checks
    BasicSecurityRule(),              # B001-B005 basic security checks
    DocumentationConsistencyRule(),  # C001-C004 documentation checks
]

# Priority map: lower number = higher priority.
# When two content findings overlap on the same line (same file_path,
# same line_start, overlapping column ranges), the higher-priority
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
    "I002_UNIMPLEMENTED_CODE": 20,
    "I003_PLACEHOLDER_RETURN": 21,
    "I004_DEBUG_BREAKPOINT": 22,
    "I001_TODO_COMMENT": 23,
    "I005_EXCESSIVE_DEBUG_OUTPUT": 120,
    "D001_PRODUCTION_START": 200,
    "D002_ENVIRONMENT_DOCUMENTATION": 201,
    "D003_DEPENDENCY_LOCK": 202,
    "D004_DEPLOYMENT_DOCUMENTATION": 203,
    "D005_DOCKER_MISSING": 204,
    "D006_DOCKER_MISSING_FROM": 205,
    "D007_DOCKER_MUTABLE_BASE": 206,
    "D008_DOCKER_ROOT_USER": 207,
    "D009_DOCKER_MISSING_START": 208,
    "D010_INVALID_DEPLOYMENT_CONFIG": 209,
    "B001_API_AUTHENTICATION": 300,
    "B002_INPUT_VALIDATION": 301,
    "B003_RATE_LIMITING": 302,
    "B004_PERMISSIVE_CORS": 303,
    "B005_SQL_INJECTION": 304,
    "C001_README_COMPLETENESS": 400,
    "C002_TECH_STACK_MISMATCH": 401,
    "C003_START_COMMAND_MISMATCH": 402,
    "C004_PROJECT_STRUCTURE_MISMATCH": 403,
}
