"""Sensitive information scanner -- rule engine, scanner core, and desensitization.

Package structure (no circular imports):
- base.py:         Base models (Finding, ScanResult, etc.) + Rule abstract class
- rules.py:        Concrete rule implementations (imports base + desensitize)
- default_rules.py: DEFAULT_RULES list + RULE_PRIORITY_MAP (imports rules)
- sensitive.py:    Scanner core -- directory traversal + dedup (imports base + default_rules)
"""
