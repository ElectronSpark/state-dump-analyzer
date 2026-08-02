from __future__ import annotations

import unittest

from router_dump_analyzer._emoji_variation_sequences import (
    EMOJI_VARIATION_SEQUENCE_PAIRS,
    EMOJI_VERSION,
    SOURCE_PAIR_COUNT,
    SOURCE_SHA256,
    SOURCE_URL,
    UNICODE_VERSION,
)
from router_dump_analyzer.public_text import (
    bounded_public_error_detail,
    contains_probable_absolute_filesystem_path,
    contains_unsafe_display_text,
    contains_unsafe_identifier_text,
    contains_unsafe_invisible_text,
    escape_unsafe_display_text,
    escape_unsafe_invisible_text,
    has_visible_identity_anchor,
    is_default_ignorable_character,
    is_unsafe_display_character,
    is_unsafe_identifier_character,
    is_unsafe_invisible_character,
)


class PublicTextBoundaryTests(unittest.TestCase):
    def test_property_rule_covers_controls_formats_unassigned_and_tags(self) -> None:
        unsafe = {
            "NUL": "\x00",
            "NEL": "\u0085",
            "NBSP": "\u00a0",
            "EM SPACE": "\u2003",
            "RLO": "\u202e",
            "LS": "\u2028",
            "TAG SPACE": "\U000e0020",
            "TAG CANCEL": "\U000e007f",
            "unassigned TAG": "\U000e0000",
            "HANGUL FILLER": "\u3164",
            "HANGUL CHOSEONG FILLER": "\u115f",
            "HANGUL JUNGSEONG FILLER": "\u1160",
            "KHMER VOWEL INHERENT AQ": "\u17b4",
            "KHMER VOWEL INHERENT AA": "\u17b5",
            "BRAILLE PATTERN BLANK": "\u2800",
            "HALFWIDTH HANGUL FILLER": "\uffa0",
            "EGYPTIAN HIEROGLYPH FULL BLANK": "\U00013441",
            "EGYPTIAN HIEROGLYPH HALF BLANK": "\U00013442",
        }
        for label, character in unsafe.items():
            with self.subTest(label=label):
                self.assertTrue(is_unsafe_invisible_character(character))
                self.assertTrue(contains_unsafe_invisible_text(f"a{character}b"))

    def test_join_controls_and_private_use_text_are_not_blanket_rejected(self) -> None:
        ordinary = "Arabic\u200cjoin\u200dcontrol Khitan\U00016fe4cluster \ue000"
        self.assertFalse(contains_unsafe_invisible_text(ordinary))
        self.assertEqual(escape_unsafe_invisible_text(ordinary), ordinary)
        self.assertTrue(has_visible_identity_anchor(ordinary))
        for unanchored in ("\u200c", "\u200d\u200c", "\ue000", "\u0301"):
            with self.subTest(unanchored=repr(unanchored)):
                self.assertFalse(has_visible_identity_anchor(unanchored))

    def test_identifier_rule_targets_default_ignorables_without_blocking_accents(
        self,
    ) -> None:
        unsafe = (
            "\u034f",  # combining grapheme joiner (Mn)
            "\ufe0e",  # variation selector 15 (Mn)
            "\ufe0f",  # variation selector 16 (Mn)
            "\U000e0100",  # supplementary variation selector (Mn)
            "\u061c",  # Arabic letter mark (Cf)
            "\ufffc",  # object replacement character (So)
            "\ue000",  # BMP private use
            "\U000f0000",  # supplementary private use
        )
        for character in unsafe:
            with self.subTest(codepoint=f"U+{ord(character):04X}"):
                self.assertTrue(is_unsafe_identifier_character(character))
                self.assertTrue(contains_unsafe_identifier_text(f"alpha{character}"))

        # These join controls have the default-ignorable property, but remain
        # the intentional identifier-policy exceptions for real shaping.
        for joiner in ("\u200c", "\u200d"):
            self.assertTrue(is_default_ignorable_character(joiner))
            self.assertFalse(is_unsafe_identifier_character(joiner))
        for legitimate in (
            "cafe\u0301",
            "شناسه\u200cشبکه",
            "क्\u200dषेत्र",
            "family\U0001f469\u200d\U0001f4bb",
        ):
            with self.subTest(legitimate=legitimate):
                self.assertFalse(contains_unsafe_identifier_text(legitimate))

    def test_display_projection_exposes_ambiguous_characters_without_rejecting_text(
        self,
    ) -> None:
        cases = (
            ("combining-grapheme-joiner", "a\u034fb", "a\\u034fb"),
            ("standard-variation-selector-1", "a\ufe00", "a\\ufe00"),
            ("standard-variation-selector-14", "a\ufe0d", "a\\ufe0d"),
            ("supplementary-variation-selector", "a\U000e0100", "a\\U000e0100"),
            ("object-replacement", "a\ufffcb", "a\\ufffcb"),
            ("bmp-private-use", "a\ue000b", "a\\ue000b"),
            ("supplementary-private-use", "a\U000f0000b", "a\\U000f0000b"),
            ("mongolian-fvs", "\u1820\u180b", "\u1820\\u180b"),
        )
        for label, raw, expected in cases:
            with self.subTest(label=label):
                self.assertTrue(contains_unsafe_display_text(raw))
                self.assertEqual(escape_unsafe_display_text(raw), expected)

        # Ordinary combining marks and shaping joiners remain valid. FE0E and
        # FE0F retain their semantics only in exact registered adjacent pairs.
        ordinary = (
            "cafe\u0301 "
            "Persian\u200cshaping "
            "family\U0001f469\u200d\U0001f4bb "
            "Khitan\U00016fe4cluster "
            "warning \u26a0\ufe0f "
            "heart \u2764\ufe0f "
            "info \u2139\ufe0f "
            "rainbow \U0001f3f3\ufe0f\u200d\U0001f308 "
            "text \u26a0\ufe0e"
        )
        self.assertFalse(contains_unsafe_display_text(ordinary))
        self.assertEqual(escape_unsafe_display_text(ordinary), ordinary)
        self.assertFalse(is_unsafe_display_character("\u0301"))
        self.assertTrue(is_unsafe_display_character("\ufe0e"))
        self.assertTrue(is_unsafe_display_character("\ufe0f"))
        self.assertTrue(is_unsafe_display_character("\ufe0d"))

    def test_display_projection_preserves_only_registered_adjacent_pairs(self) -> None:
        valid = (
            "warning \u26a0\ufe0e \u26a0\ufe0f",
            "heart \u2764\ufe0f",
            "info \u2139\ufe0f",
            "copyright \u00a9\ufe0e \u00a9\ufe0f",
            "circled M \u24c2\ufe0f",
            "keycap 1\ufe0f\u20e3",
            # Both selectors are independently valid adjacent pairs inside
            # this ZWJ sequence; preserving one must not consume the other.
            "trans flag \U0001f3f3\ufe0f\u200d\u26a7\ufe0f",
        )
        for value in valid:
            with self.subTest(value=value):
                self.assertFalse(contains_unsafe_display_text(value))
                self.assertEqual(escape_unsafe_display_text(value), value)

        invalid = (
            ("\ufe0f", "\\ufe0f"),
            ("\ufe0ealpha", "\\ufe0ealpha"),
            ("A\ufe0f", "A\\ufe0f"),
            ("1\ufe0f\ufe0f", "1\ufe0f\\ufe0f"),
            ("\u26a0\ufe0f\ufe0e", "\u26a0\ufe0f\\ufe0e"),
            ("\u24dc\ufe0f", "\u24dc\\ufe0f"),
            ("\U0001f600\ufe0f", "\U0001f600\\ufe0f"),
            ("\u0301\ufe0f", "\u0301\\ufe0f"),
            ("\u200d\ufe0f", "\u200d\\ufe0f"),
            ("\ufe0f" * 300, "\\ufe0f" * 300),
        )
        for value, expected in invalid:
            with self.subTest(value=repr(value[:20])):
                self.assertTrue(contains_unsafe_display_text(value))
                self.assertEqual(escape_unsafe_display_text(value), expected)

    def test_emoji_variation_table_has_reproducible_unicode_metadata(self) -> None:
        self.assertEqual(UNICODE_VERSION, "15.0.0")
        self.assertEqual(EMOJI_VERSION, "15.0")
        self.assertEqual(SOURCE_PAIR_COUNT, 708)
        self.assertEqual(len(EMOJI_VARIATION_SEQUENCE_PAIRS), SOURCE_PAIR_COUNT)
        self.assertEqual(
            SOURCE_URL,
            "https://www.unicode.org/Public/15.0.0/ucd/emoji/"
            "emoji-variation-sequences.txt",
        )
        self.assertEqual(
            SOURCE_SHA256,
            "731a630518c4a51c480c407ec10f3476ebe0afc582c7c20c7304f966133cf118",
        )

    def test_display_projection_is_injective_for_literal_escape_text(self) -> None:
        projected = escape_unsafe_display_text(
            "state\u034fchanged",
            make_escapes_unambiguous=True,
        )
        literal = escape_unsafe_display_text(
            "state\\u034fchanged",
            make_escapes_unambiguous=True,
        )
        self.assertEqual(projected, "state\\u034fchanged")
        self.assertEqual(literal, "state\\\\u034fchanged")
        self.assertNotEqual(projected, literal)

        emoji = escape_unsafe_display_text(
            "warning \u26a0\ufe0f",
            make_escapes_unambiguous=True,
        )
        literal_selector = escape_unsafe_display_text(
            "warning \u26a0\\ufe0f",
            make_escapes_unambiguous=True,
        )
        self.assertEqual(emoji, "warning \u26a0\ufe0f")
        self.assertEqual(literal_selector, "warning \u26a0\\\\ufe0f")
        self.assertNotEqual(emoji, literal_selector)

    def test_ordinary_unicode_and_prose_whitespace_are_preserved(self) -> None:
        ordinary = "cafe\u0301 中文 😀\tfirst\nsecond\rthird"
        self.assertFalse(
            contains_unsafe_invisible_text(
                ordinary,
                allow_prose_whitespace=True,
            )
        )
        self.assertEqual(
            escape_unsafe_invisible_text(ordinary),
            ordinary,
        )
        self.assertTrue(contains_unsafe_invisible_text(ordinary))

    def test_escape_is_unambiguous_for_bmp_and_supplementary_characters(self) -> None:
        value = "safe\u2028tag:\U000e0061:end"
        self.assertEqual(
            escape_unsafe_invisible_text(value),
            "safe\\u2028tag:\\U000e0061:end",
        )

    def test_absolute_host_paths_are_detected_without_treating_urls_as_paths(
        self,
    ) -> None:
        for value in (
            r"failed at C:\private\tenant\state.sqlite3",
            "failed at C:/private/tenant/state.sqlite3",
            r'failed at "C:\private\tenant\state.sqlite3"',
            r"path=C:\private\tenant\state.sqlite3",
            r"[C:\private\tenant\state.sqlite3]",
            r"failed at \\server\share\state.sqlite3",
            r'failed at "\\server\share\state.sqlite3"',
            r"path=\\server\share\state.sqlite3",
            "//server/share/state.sqlite3",
            "failed at /srv/private/tenant/state.sqlite3",
            'failed at "/srv/private/tenant/state.sqlite3"',
            "path=/srv/private/tenant/state.sqlite3",
            "[/srv/private/tenant/state.sqlite3]",
            "file:///srv/private/tenant/state.sqlite3",
            "sqlite:///C:/private/tenant/state.sqlite3",
            "path=/2001:db8::/64",
            "path=/::/0",
            "failed at /fe80::1/128",
            r"failed below %APPDATA%\router-dump\state.sqlite3",
            r"failed below $env:LOCALAPPDATA\router-dump\state.sqlite3",
            r"failed below ${env:APPDATA}\router-dump\state.sqlite3",
            "failed below $HOME/.local/state/router-dump",
            "failed below ${XDG_STATE_HOME}/router-dump",
            "failed below ~/.local/state/router-dump",
            "failed below ~operator/router-dump",
            r"failed below \private\tenant\state.sqlite3",
            r"path=\private\tenant\state.sqlite3",
            r"failed below ..\private\tenant\state.sqlite3",
            "failed below ../private/tenant/state.sqlite3",
            "failed below ../../private/state.sqlite3",
            "failed below package/../private/state.sqlite3",
        ):
            with self.subTest(value=value):
                self.assertTrue(contains_probable_absolute_filesystem_path(value))
        for value in (
            "invalid URL https://example.test/v1/resource",
            "invalid route /v1/resource",
            "invalid prefix 2001:db8::/64",
            "invalid prefix fd00::/8",
            "invalid prefix ::/0",
            "invalid prefix [2001:db8:1::/64]",
            "next-hop fe80::1/128 is invalid",
            "generated forwarding row for scenario/node-a is inconsistent",
            "opaque:key/compound-part remains caller-facing",
            "plugin.resource/member is not a host path",
            "vrf/2001:db8::/64 is an opaque router key",
            "literal %APPDATA% without a child path",
            "literal $HOME without a child path",
            "cost~value/member is an opaque key",
            "invalid URL https://example.test/$HOME/resource",
            r"literal \u034fchanged is an explicit projection",
            r"literal \U000e0061 is an explicit projection",
            r"opaque member..backup/resource remains caller-facing",
        ):
            with self.subTest(value=value):
                self.assertFalse(contains_probable_absolute_filesystem_path(value))

        self.assertTrue(
            contains_probable_absolute_filesystem_path(
                "prefix 2001:db8::/64 failed at /srv/private/state.sqlite3"
            )
        )

    def test_public_error_detail_is_bounded_by_one_shared_policy(self) -> None:
        fallback = "request was rejected"
        self.assertEqual(
            bounded_public_error_detail("safe caller value", fallback=fallback),
            "safe caller value",
        )
        for value in (
            "",
            "bad\u202edetail",
            "bad\u3164detail",
            "path=/srv/private/state.sqlite3",
            r"path=%APPDATA%\router-dump\state.sqlite3",
            r"path=$env:LOCALAPPDATA\router-dump\state.sqlite3",
            "path=$HOME/.local/state/router-dump",
            "path=${XDG_STATE_HOME}/router-dump",
            "path=~/.local/state/router-dump",
            "x" * 1_025,
            {"not": "text"},
        ):
            with self.subTest(value=repr(value)):
                self.assertEqual(
                    bounded_public_error_detail(value, fallback=fallback),
                    fallback,
                )

    def test_public_error_detail_visibly_projects_display_ambiguity(self) -> None:
        fallback = "request was rejected"
        self.assertEqual(
            bounded_public_error_detail(
                "emoji \u26a0\ufe0f, Mongolian \u1820\u180b, PUA \ue000, object \ufffc",
                fallback=fallback,
            ),
            "emoji \u26a0\ufe0f, Mongolian \u1820\\u180b, PUA \\ue000, object \\ufffc",
        )
        raw = bounded_public_error_detail("state\u034fchanged", fallback=fallback)
        literal = bounded_public_error_detail("state\\u034fchanged", fallback=fallback)
        self.assertEqual(raw, "state\\u034fchanged")
        self.assertEqual(literal, "state\\\\u034fchanged")
        self.assertNotEqual(raw, literal)
        self.assertEqual(
            bounded_public_error_detail(raw, fallback=fallback),
            raw,
        )

        # Expansion, rather than only the raw input length, owns the public
        # response budget.
        self.assertEqual(
            bounded_public_error_detail(
                "abcde\ufe0d",
                fallback="rejected",
                maximum_characters=10,
            ),
            "rejected",
        )
        with self.assertRaisesRegex(ValueError, "fallback"):
            bounded_public_error_detail(
                "safe",
                fallback="bad\ufe0d",
            )


if __name__ == "__main__":
    unittest.main()
