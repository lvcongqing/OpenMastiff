from __future__ import annotations

from urllib.parse import quote, urlparse, urlunparse


def https_url_with_token(url: str, username: str, token: str) -> str:
    """Embed HTTP basic credentials into an https URL for non-interactive git clone."""
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        raise ValueError("http_token credential requires an http(s) repo_url")
    host = p.hostname or ""
    port = p.port
    userinfo = f"{quote(username, safe='')}:{quote(token, safe='')}"
    if port:
        netloc = f"{userinfo}@{host}:{port}"
    else:
        netloc = f"{userinfo}@{host}"
    return urlunparse((p.scheme, netloc, p.path, p.params, p.query, p.fragment))


def git_ssh_command(private_key_path: str) -> str:
    """GIT_SSH_COMMAND value: isolate identity and avoid host key prompts blocking workers."""
    return f'ssh -i "{private_key_path}" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new'
