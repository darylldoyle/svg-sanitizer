# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Security

- Strip the `DOCTYPE`/DTD from the input before parsing. This prevents custom
  entity definitions (which can collide with HTML5 named character references,
  e.g. `<!ENTITY Tab "#">` resolving `&Tab;` to U+0009 once inlined into HTML)
  and DTD-defaulted attributes from ever reaching the XML parser.
- Broaden the remote-reference detection used by `removeRemoteReferences(true)`
  so previously-missed remote references are stripped.
- Strip remote references from inline `<style>` content more thoroughly under
  `removeRemoteReferences(true)`: CSS escapes and comments are resolved before
  matching (so `\75 rl(…)` or `@\69 mport "…"` cannot hide), escaped or
  whitespace-separated `@import` is handled, and the bare-string form of
  `image-set()` / `-webkit-image-set()` is covered. This remains best-effort — a
  regex-based stripper cannot see through every CSS construct (the bare-string
  forms of `image()` / `src()` are not handled), so untrusted CSS should still be
  isolated at the embedding boundary.
- Harden DTD stripping to skip comments and quoted strings while scanning the
  internal subset, so a `]` inside a DTD comment or entity value can no longer
  truncate the scan early and leave a DTD fragment behind. The `DOCTYPE` is now
  removed correctly by construction.

### Changed

- **Potentially breaking:** an SVG/XML document that references a **custom DTD
  entity** is now rejected — `sanitize()` returns `false` — instead of being
  cleaned. Because the DTD is stripped before parsing, the entity reference
  becomes undefined and libxml rejects the document (fail-safe). A `PUBLIC`
  `DOCTYPE` with no entity references (e.g. a typical Illustrator/Inkscape
  export) still sanitizes normally.
- **Behaviour change (opt-in only):** with `removeRemoteReferences(true)`, remote
  references are now detected and removed in more places — bare remote
  `href`/`src` values, unquoted `url(...)` references, `url(...)` embedded among
  other declarations in a `style` attribute, and remote `@import`/`url(...)`
  inside `<style>` element text. Previously only a whole-value, quoted `url(...)`
  was matched. Local (`/path`) and fragment (`#id`) references are still
  preserved.
