"""Shared exact and wildcard hostname scope matching."""


def host_matches(pattern: str, host: str) -> bool:
    """Match an exact host or a leading-wildcard subdomain pattern."""

    normalized_pattern = pattern.strip().lower().rstrip(".")
    normalized_host = host.strip().lower().rstrip(".")
    if normalized_pattern == "*":
        return True
    if normalized_pattern.startswith("*."):
        suffix = normalized_pattern[2:]
        return bool(suffix) and normalized_host.endswith(f".{suffix}")
    return normalized_host == normalized_pattern


def host_is_covered(host: str, patterns: list[str]) -> bool:
    """Return whether any configured scope pattern covers the host."""

    return any(host_matches(pattern, host) for pattern in patterns)


def hosts_are_covered(hosts: set[str], patterns: list[str]) -> bool:
    """Return whether every observed host has explicit exact or wildcard coverage."""

    return all(host_is_covered(host, patterns) for host in hosts)
