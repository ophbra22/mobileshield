"""Fail-closed URL authorization and disposable, deadline-bounded DNS workers."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import multiprocessing
import re
import socket
import time
import unicodedata
from urllib.parse import quote, urlsplit, urlunsplit


class DestinationBlocked(ValueError):
    def __init__(self):
        super().__init__('destination_blocked')


@dataclass(frozen=True)
class NetworkTarget:
    url: str
    scheme: str
    hostname: str
    port: int
    path_query: str


# Conservative exclusions supplement Python 3.11's older address registry.
# Transition mechanisms can route an apparently global IPv6 address to IPv4.
_EXCLUDED = tuple(ipaddress.ip_network(net) for net in (
    '192.0.0.0/24', '192.88.99.0/24',
    '64:ff9b::/96', '64:ff9b:1::/48', '2001::/23', '2002::/16',
))
_INTERNAL_SUFFIXES = ('localhost', 'local', 'localdomain', 'internal', 'home',
                      'lan', 'invalid', 'test', 'onion', 'arpa')


def ambiguous_url_text(value: str) -> bool:
    return any(c.isspace() or unicodedata.category(c).startswith('C')
               or c == '\\' for c in value)


def public_address(value: str) -> str:
    """Validate numeric answers independently of resolver/connector injection."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise DestinationBlocked() from None
    if ('%' in value or not address.is_global or address.is_reserved
            or address.is_multicast or address.is_unspecified or address.is_loopback
            or address.is_link_local or address.is_private
            or getattr(address, 'is_site_local', False)
            or getattr(address, 'ipv4_mapped', None) is not None
            or any(address.version == net.version and address in net for net in _EXCLUDED)):
        raise DestinationBlocked()
    return str(address)


def validate_raw_authority(parts) -> None:
    """Reject malformed authority facts before either parser reconstructs it."""
    host = parts.hostname
    if (not parts.netloc or '@' in parts.netloc or not host or '%' in host
            or parts.netloc.endswith(':') or host.endswith('..')):
        raise DestinationBlocked()
    if parts.netloc.startswith('[') and not re.fullmatch(r'\[[0-9a-fA-F:.]+\](?::[0-9]+)?', parts.netloc):
        raise DestinationBlocked()


def canonical_target(url: str) -> NetworkTarget:
    """Authorize syntax and literal addresses; DNS authorization is separate."""
    if (not isinstance(url, str) or not url or len(url) > 16384
            or ambiguous_url_text(url)):
        raise DestinationBlocked()
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in ('http', 'https'):
            raise DestinationBlocked()
        validate_raw_authority(parts)
        host = parts.hostname
        port = parts.port
        expected_port = 443 if scheme == 'https' else 80
        if port is not None and port != expected_port:
            raise DestinationBlocked()
        host = host.removesuffix('.').lower()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            # Reject inet_aton-style abbreviated, octal, hex and integer forms.
            if all(re.fullmatch(r'(?:[0-9]+|0x[0-9a-f]+)', label)
                   for label in host.split('.')):
                raise DestinationBlocked()
            host = host.encode('idna').decode('ascii').lower()
            labels = host.split('.')
            if (len(labels) < 2 or len(host) > 253
                    or all(re.fullmatch(r'(?:[0-9]+|0x[0-9a-f]+)', label) for label in labels)
                    or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                           for label in labels)
                    or any(host == suffix or host.endswith('.' + suffix)
                           for suffix in _INTERNAL_SUFFIXES)):
                raise DestinationBlocked()
        else:
            host = public_address(host)
        authority = f'[{host}]' if ':' in host else host
        path = quote(parts.path or '/', safe="/%:@!$&'()*+,;=-._~")
        query = quote(parts.query, safe="/%?:@!$&'()*+,;=-._~")
        canonical = urlunsplit((scheme, authority, path, query, ''))
        return NetworkTarget(canonical, scheme, host, expected_port,
                             path + ('?' + query if query else ''))
    except (ValueError, UnicodeError):
        raise DestinationBlocked() from None


def _dns_worker(pipe, hostname: str, port: int) -> None:
    """Only this disposable child invokes the platform resolver."""
    try:
        records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        if not records or len(records) > 64:
            pipe.send(('error', []))
        else:
            pipe.send(('ok', [record[4][0] for record in records]))
    except Exception:
        pipe.send(('error', []))
    finally:
        pipe.close()


def resolve_public(target: NetworkTarget, *, deadline: float) -> tuple[str, ...]:
    if time.monotonic() >= deadline:
        raise TimeoutError('deadline_exceeded')
    try:
        ipaddress.ip_address(target.hostname)
    except ValueError:
        pass
    else:
        return (public_address(target.hostname),)
    # Spawn avoids inheriting locks from a multithreaded web-server process.
    context = multiprocessing.get_context('spawn')
    receiving, sending = context.Pipe(duplex=False)
    process = context.Process(target=_dns_worker, args=(sending, target.hostname, target.port),
                              daemon=True)
    started = False
    try:
        process.start()
        started = True
        sending.close()
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not receiving.poll(remaining):
            raise TimeoutError('deadline_exceeded')
        status, answers = receiving.recv()
        if time.monotonic() >= deadline:
            raise TimeoutError('deadline_exceeded')
        if status != 'ok' or not answers:
            raise OSError('inspection_failed')
        return tuple(dict.fromkeys(public_address(answer) for answer in answers))
    except (EOFError, BrokenPipeError):
        raise OSError('inspection_failed') from None
    finally:
        sending.close()
        receiving.close()
        if started:
            # Terminate before joining; never leave a getaddrinfo worker running.
            if process.is_alive():
                process.terminate()
            process.join(timeout=.05)
            if process.is_alive():
                process.kill()
                process.join()
            process.close()
