"""Shared Unicode safety rules for human- and AI-facing text boundaries.

The boundary is intentionally property based.  Enumerating today's known
formatting controls misses whole classes of invisible characters, including
Unicode TAG characters and code points that are unassigned in the runtime's
Unicode database.  Callers can preserve ordinary ASCII prose whitespace while
still making every other control, format, separator, surrogate, or unassigned
code point explicit.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata

from ._emoji_variation_sequences import EMOJI_VARIATION_SEQUENCE_PAIRS

_ORDINARY_PROSE_CONTROLS = frozenset({"\t", "\n", "\r"})
_SAFE_FORMAT_CHARACTERS = frozenset({"\u200c", "\u200d"})
# U+FE0E TEXT PRESENTATION SELECTOR and U+FE0F EMOJI PRESENTATION SELECTOR
# carry standardized typographic meaning only in registered adjacent pairs.
# The string-level display scanner recognizes those exact pairs.  Identifier
# admission and this context-free character predicate continue to reject both.
_DISPLAY_VARIATION_SELECTORS = frozenset({"\ufe0e", "\ufe0f"})
# Unicode 15 ``Default_Ignorable_Code_Point`` ranges.  Python's stdlib exposes
# general categories but not this derived binary property, and rejecting all
# ``Mn`` characters would also reject ordinary combining accents.  Keep this
# compact property table explicit and update it with the Python/Unicode
# baseline.  The broad supplementary range intentionally includes TAG
# characters, variation-selector supplement characters, and its reserved
# default-ignorable code points.
_DEFAULT_IGNORABLE_CODE_POINT_RANGES = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)
# Reviewed against Unicode 15.0.0. Re-sweep assigned blank/filler characters
# whenever the project's Python/Unicode database baseline changes; do not infer
# this set from names or combining categories because those include legitimate
# shaping controls and visible symbols.
_ASSIGNED_INVISIBLE_CHARACTERS = frozenset(
    {
        "\u115f",  # HANGUL CHOSEONG FILLER
        "\u1160",  # HANGUL JUNGSEONG FILLER
        "\u17b4",  # KHMER VOWEL INHERENT AQ
        "\u17b5",  # KHMER VOWEL INHERENT AA
        "\u2800",  # BRAILLE PATTERN BLANK
        "\u3164",  # HANGUL FILLER
        "\uffa0",  # HALFWIDTH HANGUL FILLER
        "\U00013441",  # EGYPTIAN HIEROGLYPH FULL BLANK
        "\U00013442",  # EGYPTIAN HIEROGLYPH HALF BLANK
    }
)
_UNSAFE_INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cn", "Cs", "Zl", "Zp"})
# Web URLs are useful caller-facing diagnostics and do not describe the local
# host layout. Other schemes fail closed: for example ``sqlite:///C:/...`` and
# similar DSNs can embed storage paths or credentials.
_NETWORK_URL = re.compile(r"(?i)\bhttps?://[^\s<>]+")
_FILE_URL = re.compile(r"(?i)\bfile:(?://|/)[^\s<>]+")
_WINDOWS_DRIVE_PATH = re.compile(r"(?i)[a-z]:[\\/]")
_BACKSLASH_UNC_PATH = re.compile(r"\\\\[^\\/\s]+[\\/][^\\/\s]+")
_FORWARD_SLASH_UNC_PATH = re.compile(r"//[^/\s]+/[^/\s]+")
# A Windows root-relative path has no drive letter, but still discloses a
# machine-local coordinate.  Require a second component so an isolated
# backslash in prose or an escaped character is not treated as a path.  The
# explicit Unicode-escape exclusion keeps this detector compatible with the
# injective display projection below.
_ROOTED_BACKSLASH_PATH = re.compile(
    r"(?<![\w.~\\/-])\\(?!\\)"
    r"(?!(?:u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})(?:\b|\\))"
    r"[^\\/\s\"'<>]+[\\/][^\s\"'<>]+"
)
# Relative traversal can reveal the same host layout as an absolute path once
# an exception includes the resolved child.  Match at a token/path boundary;
# ordinary dotted resource keys such as ``member..backup`` stay visible.
_TRAVERSAL_PATH = re.compile(
    r"(?<![\w.~\-])(?:\.\.[\\/])+(?=[^\\/\s\"'<>])"
)
# Symbolic home/configuration paths can disclose host layout just as surely as
# an expanded absolute path.  Cover the five common syntaxes without trying
# to guess which environment-variable names exist on the host.
_CMD_VARIABLE_PATH = re.compile(r"(?i)%[a-z_][a-z0-9_]*%[\\/]")
_POWERSHELL_VARIABLE_PATH = re.compile(r"(?i)(?<![\w$])\$env:[a-z_][a-z0-9_]*[\\/]")
_BRACED_SHELL_VARIABLE_PATH = re.compile(
    r"(?i)(?<![\w$])\$\{(?:env:)?[a-z_][a-z0-9_]*\}[\\/]"
)
_SHELL_VARIABLE_PATH = re.compile(r"(?<![\w$])\$[A-Za-z_][A-Za-z0-9_]*[\\/]")
_TILDE_HOME_PATH = re.compile(r"(?<![\w])~(?:[A-Za-z0-9._-]+)?[\\/]")
_IPV6_CIDR_CANDIDATE = re.compile(
    r"(?<![0-9A-Fa-f:%])(?:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*)/[0-9]{1,3}(?![0-9])"
)
# A POSIX absolute path starts at a token boundary. A slash inside an opaque
# identifier such as ``scenario/node`` is a relationship separator, not a
# host-root marker. Assignment, quoting, brackets, and punctuation remain
# valid boundaries, so diagnostics such as ``path=/srv/private`` still close.
_POSIX_PATH_CANDIDATE = re.compile(r"(?<![\w.~\-])/(?!/)[^\s\"'<>]*")
_RELATIVE_API_ROUTE = re.compile(
    r"/(?:api|v[0-9]+)(?:/[A-Za-z0-9._~!$&()*+,;=:@%-]+)+/?\Z",
    re.IGNORECASE,
)


class _ProjectedPublicText(str):
    """Trusted marker preventing duplicate projection across adapter layers."""


def is_unsafe_invisible_character(
    character: str,
    *,
    allow_prose_whitespace: bool = False,
) -> bool:
    """Return whether one character is unsafe at a public text boundary.

    ``Cf`` covers bidirectional controls, unsafe zero-width formatting, and
    the assigned Unicode TAG characters. U+200C ZERO WIDTH NON-JOINER and
    U+200D ZERO WIDTH JOINER are the exact exceptions because they carry
    legitimate shaping semantics in ordinary text. ``Cn`` covers the
    unassigned portion of the TAG block and future invisible code points until
    Python's Unicode database assigns them. Assigned non-``Cf`` fillers and
    blank glyphs with invisible rendering are rejected explicitly. Every
    ``Zs`` separator except ordinary ASCII space is explicit as well,
    preventing visually blank identifier distinctions. U+16FE4 KHITAN SMALL
    SCRIPT FILLER remains valid because it is an orthographic cluster-layout
    control; like join controls, it cannot anchor an identity by itself.

    Private-use (``Co``) text is not blanket-rejected: a deployment font may
    render it visibly. Public surfaces bound the containing value's length,
    and callers must not use private-use glyphs as the sole semantic identity.
    """

    if not isinstance(character, str) or len(character) != 1:
        raise ValueError("character must contain exactly one Unicode character")
    if allow_prose_whitespace and character in _ORDINARY_PROSE_CONTROLS:
        return False
    if character in _SAFE_FORMAT_CHARACTERS:
        return False
    if character in _ASSIGNED_INVISIBLE_CHARACTERS:
        return True
    category = unicodedata.category(character)
    return category in _UNSAFE_INVISIBLE_CATEGORIES or (
        category == "Zs" and character != " "
    )


def is_default_ignorable_character(character: str) -> bool:
    """Return whether one character has Unicode's default-ignorable property."""

    if not isinstance(character, str) or len(character) != 1:
        raise ValueError("character must contain exactly one Unicode character")
    codepoint = ord(character)
    return any(
        first <= codepoint <= last
        for first, last in _DEFAULT_IGNORABLE_CODE_POINT_RANGES
    )


def is_unsafe_identifier_character(character: str) -> bool:
    """Return whether a character can create a spoofed catalog identity.

    U+200C and U+200D remain the deliberate join-control exceptions required
    by Persian, Arabic, Indic, and emoji shaping.  Other default-ignorable
    characters are rejected even when their general category is ``Mn``.
    Object replacement and private-use characters are also inappropriate for
    an authorization/storage identity because their visible rendering is
    missing or deployment-font dependent.
    """

    if not isinstance(character, str) or len(character) != 1:
        raise ValueError("character must contain exactly one Unicode character")
    if character in _SAFE_FORMAT_CHARACTERS:
        return False
    return (
        is_default_ignorable_character(character)
        or is_unsafe_invisible_character(character)
        or character == "\ufffc"
        or unicodedata.category(character) == "Co"
    )


def contains_unsafe_identifier_text(value: str) -> bool:
    """Return whether caller-owned identity text contains spoofing material."""

    return any(is_unsafe_identifier_character(character) for character in value)


def is_unsafe_display_character(
    character: str,
    *,
    allow_prose_whitespace: bool = False,
) -> bool:
    """Return whether a character must be made explicit when displayed.

    This is deliberately a projection rule, not an admission rule.  Labels may
    legitimately contain emoji or Mongolian variation selectors and a
    deployment may assign visible glyphs to private-use code points.  Public
    and AI-facing surfaces therefore preserve the surrounding text while
    rendering ambiguous selectors or font-dependent characters as visible
    Unicode escapes.  This context-free predicate treats U+FE0E and U+FE0F as
    unsafe.  The string-level scanner preserves either selector only when its
    immediately preceding code point forms an exact pair registered by
    Unicode's versioned ``emoji-variation-sequences.txt`` table.  ZWNJ and ZWJ
    remain the format-control exceptions needed for real-script and emoji
    shaping.
    """

    if not isinstance(character, str) or len(character) != 1:
        raise ValueError("character must contain exactly one Unicode character")
    if character in _SAFE_FORMAT_CHARACTERS:
        return False
    return (
        is_unsafe_invisible_character(
            character,
            allow_prose_whitespace=allow_prose_whitespace,
        )
        or is_default_ignorable_character(character)
        or character == "\ufffc"
        or unicodedata.category(character) == "Co"
    )


def _is_unsafe_display_character_at(
    value: str,
    index: int,
    *,
    allow_prose_whitespace: bool,
) -> bool:
    """Apply display safety with the exact adjacent-pair selector exception."""

    character = value[index]
    if character in _DISPLAY_VARIATION_SELECTORS:
        return index == 0 or (
            ord(value[index - 1]),
            ord(character),
        ) not in EMOJI_VARIATION_SEQUENCE_PAIRS
    return is_unsafe_display_character(
        character,
        allow_prose_whitespace=allow_prose_whitespace,
    )


def contains_unsafe_display_text(
    value: str,
    *,
    allow_prose_whitespace: bool = False,
) -> bool:
    """Return whether ``value`` needs public-display projection."""

    return any(
        _is_unsafe_display_character_at(
            value,
            index,
            allow_prose_whitespace=allow_prose_whitespace,
        )
        for index in range(len(value))
    )


def contains_unsafe_invisible_text(
    value: str,
    *,
    allow_prose_whitespace: bool = False,
) -> bool:
    """Return whether ``value`` contains an unsafe invisible character."""

    return any(
        is_unsafe_invisible_character(
            character,
            allow_prose_whitespace=allow_prose_whitespace,
        )
        for character in value
    )


def has_visible_identity_anchor(value: str) -> bool:
    """Return whether text has a character that can anchor visible identity.

    Join controls are safe inside ordinary shaped text, but a value made only
    from them is visually empty. Private-use glyphs are font-dependent and
    combining marks need a base, so neither can be the sole anchor for a
    caller-owned identifier or label. Letters, numbers, punctuation, and
    symbols provide an unambiguous visible anchor while still permitting
    joiners, combining marks, and private-use glyphs around that anchor.
    """

    return any(
        unicodedata.category(character)[0] in {"L", "N", "P", "S"}
        and unicodedata.category(character) != "Co"
        for character in value
    )


def escape_unsafe_invisible_text(
    value: str,
    *,
    allow_prose_whitespace: bool = True,
) -> str:
    """Render unsafe invisible characters as unambiguous text escapes."""

    escaped: list[str] = []
    for character in value:
        if not is_unsafe_invisible_character(
            character,
            allow_prose_whitespace=allow_prose_whitespace,
        ):
            escaped.append(character)
            continue
        codepoint = ord(character)
        escaped.append(
            f"\\u{codepoint:04x}" if codepoint <= 0xFFFF else f"\\U{codepoint:08x}"
        )
    return "".join(escaped)


def escape_unsafe_display_text(
    value: str,
    *,
    allow_prose_whitespace: bool = True,
    make_escapes_unambiguous: bool = False,
) -> str:
    """Project display-unsafe characters as visible Unicode escapes.

    When ``make_escapes_unambiguous`` is true, every caller-supplied
    backslash is doubled before generated ``\\u``/``\\U`` escapes are added.
    The projection is then injective: literal escape-looking input cannot
    collide with the corresponding Unicode character.
    """

    escaped: list[str] = []
    for index, character in enumerate(value):
        if make_escapes_unambiguous and character == "\\":
            escaped.append("\\\\")
            continue
        if not _is_unsafe_display_character_at(
            value,
            index,
            allow_prose_whitespace=allow_prose_whitespace,
        ):
            escaped.append(character)
            continue
        codepoint = ord(character)
        escaped.append(
            f"\\u{codepoint:04x}" if codepoint <= 0xFFFF else f"\\U{codepoint:08x}"
        )
    return "".join(escaped)


def bounded_public_error_detail(
    value: object,
    *,
    fallback: str,
    maximum_characters: int = 1_024,
) -> str:
    """Return one bounded caller-safe detail string or a closed fallback.

    The check is shared by every HTTP adapter boundary. Unsafe controls and
    probable absolute host paths select the fixed fallback. Default-ignorable,
    object-replacement, and private-use characters are instead rendered as
    visible escapes so an otherwise useful internationalized diagnostic is
    retained. Caller backslashes are doubled to keep that projection
    injective, and the total character budget is checked again after expansion.
    """

    if type(maximum_characters) is not int or maximum_characters < 1:
        raise ValueError("maximum_characters must be a positive integer")
    if (
        type(fallback) is not str
        or not fallback
        or len(fallback) > maximum_characters
        or contains_unsafe_display_text(fallback)
        or contains_probable_absolute_filesystem_path(fallback)
    ):
        raise ValueError("fallback must be bounded public text")
    if type(value) is _ProjectedPublicText:
        if (
            not value
            or len(value) > maximum_characters
            or contains_unsafe_display_text(value)
            or contains_probable_absolute_filesystem_path(value)
        ):
            return fallback
        return value
    if (
        type(value) is not str
        or not value
        or len(value) > maximum_characters
        or contains_unsafe_invisible_text(value)
        or contains_probable_absolute_filesystem_path(value)
    ):
        return fallback
    projected = escape_unsafe_display_text(
        value,
        allow_prose_whitespace=False,
        make_escapes_unambiguous=True,
    )
    if len(
        projected
    ) > maximum_characters or contains_probable_absolute_filesystem_path(projected):
        return fallback
    return _ProjectedPublicText(projected)


def _without_ipv6_cidr_tokens(value: str) -> str:
    """Blank syntactically valid IPv6 prefixes without hiding adjacent text."""

    def replace(match: re.Match[str]) -> str:
        preceding_slash = match.start() - 1
        if (
            preceding_slash >= 0
            and value[preceding_slash] == "/"
            and _POSIX_PATH_CANDIDATE.match(value, preceding_slash) is not None
        ):
            # A root-looking slash owns the following token even when the
            # token is also a valid IPv6 prefix. By contrast, the slash in an
            # opaque key such as ``vrf/2001:db8::/64`` is not at a POSIX token
            # boundary, so its CIDR is still blanked before path scanning.
            return match.group(0)
        try:
            network = ipaddress.ip_network(match.group(0), strict=False)
        except ValueError:
            return match.group(0)
        if network.version != 6:
            return match.group(0)
        return " " * len(match.group(0))

    return _IPV6_CIDR_CANDIDATE.sub(replace, value)


def contains_probable_absolute_filesystem_path(
    value: str,
    *,
    allow_api_routes: bool = True,
) -> bool:
    """Return whether public text appears to contain an absolute host path.

    Error details are not a transport for storage diagnostics.  The check is
    intentionally conservative: a false positive only selects the endpoint's
    documented safe fallback, while a false negative could disclose host
    layout or tenant storage coordinates. Public error text may opt into the
    narrow API-route exception; durable identity fields must set
    ``allow_api_routes=False`` because a route-shaped value can also be an
    absolute POSIX path.
    """

    if _FILE_URL.search(value) is not None:
        return True

    # Network URLs are not host paths. Remove them before delimiter-independent
    # scanning so their authority and URL-path components cannot be mistaken
    # for UNC or POSIX filesystem syntax.
    candidate = _without_ipv6_cidr_tokens(_NETWORK_URL.sub("", value))
    if (
        _WINDOWS_DRIVE_PATH.search(candidate) is not None
        or _BACKSLASH_UNC_PATH.search(candidate) is not None
        or _FORWARD_SLASH_UNC_PATH.search(candidate) is not None
        or _ROOTED_BACKSLASH_PATH.search(candidate) is not None
        or _TRAVERSAL_PATH.search(candidate) is not None
        or _CMD_VARIABLE_PATH.search(candidate) is not None
        or _POWERSHELL_VARIABLE_PATH.search(candidate) is not None
        or _BRACED_SHELL_VARIABLE_PATH.search(candidate) is not None
        or _SHELL_VARIABLE_PATH.search(candidate) is not None
        or _TILDE_HOME_PATH.search(candidate) is not None
    ):
        return True

    for match in _POSIX_PATH_CANDIDATE.finditer(candidate):
        if match.start() > 0 and candidate[match.start() - 1] == "/":
            continue
        token = match.group(0).rstrip("),.;:]}!")
        if not token or token == "/":
            continue
        # API routes are common caller-facing validation values rather than
        # host coordinates. This narrow exception avoids hiding `/v1/...`
        # diagnostics while all other absolute-looking paths fail closed.
        if allow_api_routes and _RELATIVE_API_ROUTE.fullmatch(token) is not None:
            continue
        return True
    return False


def contains_filesystem_identity_path(value: str) -> bool:
    """Reject every path-shaped value from durable identity fields.

    Unlike public diagnostics, identity vocabulary has no reason to preserve
    route-shaped strings. Separators, dot-relative tokens, and Windows
    drive-relative prefixes therefore fail closed even when they are not
    absolute host paths.
    """

    return (
        "/" in value
        or "\\" in value
        or value in {".", ".."}
        or (
            len(value) >= 2
            and value[0].isascii()
            and value[0].isalpha()
            and value[1] == ":"
        )
        or contains_probable_absolute_filesystem_path(
            value,
            allow_api_routes=False,
        )
    )


__all__ = [
    "bounded_public_error_detail",
    "contains_filesystem_identity_path",
    "contains_probable_absolute_filesystem_path",
    "contains_unsafe_display_text",
    "contains_unsafe_identifier_text",
    "contains_unsafe_invisible_text",
    "escape_unsafe_display_text",
    "escape_unsafe_invisible_text",
    "has_visible_identity_anchor",
    "is_default_ignorable_character",
    "is_unsafe_display_character",
    "is_unsafe_identifier_character",
    "is_unsafe_invisible_character",
]
