# Rule language reference

REA rules are plain text files (`.rea`, or `.yar` / `.yara` if you prefer). The
syntax is close to YARA so existing knowledge transfers, but the engine is a
small pure-Python implementation with no binary dependency.

## Anatomy of a rule

```
rule Ransom_Note_Text
{
    meta:
        author      = "rea-team"
        severity    = "high"
        score       = 30
        description = "Classic ransomware note language"

    strings:
        $a = "your files have been encrypted" nocase
        $b = "send bitcoin" nocase
        $hex = { 4D 5A ?? 90 }
        $rx  = /[A-Z]:\\Users\\[^\\]+/ nocase

    condition:
        any of ($a*) or $hex or $rx
}
```

Every rule needs a `condition`. `meta`, `strings` and tags are optional. A rule
with no strings is legal and useful, for example `condition: filesize > 5MB`.

## Meta

`meta` holds free-form key/value pairs. Three keys are interpreted:

| Key | Effect |
| --- | --- |
| `severity` | `info`, `low`, `medium`, `high` or `critical`. Drives report grouping and the `--min-severity` gate. |
| `score` | Integer added to the artifact's risk score when the rule matches. |
| `description` | Human-readable summary shown in reports. |

Other keys such as `author` and `reference` are preserved and reported.

## Strings

Three kinds, chosen by the delimiters:

| Kind | Syntax | Notes |
| --- | --- | --- |
| Text | `$a = "literal text"` | Escapes: `\n \r \t \\ \" \0` |
| Hex | `$a = { 4D 5A ?? 90 }` | `??` matches any byte; `4?` and `?A` match on one nibble |
| Regex | `$a = /pattern/` | Python `re` syntax over bytes |

Modifiers follow the value:

| Modifier | Effect |
| --- | --- |
| `nocase` | Case-insensitive matching |
| `wide` | Also match the UTF-16LE encoding of the pattern |
| `ascii` | Explicit default, no effect |
| `fullword` | Accepted for YARA compatibility; anchoring is not enforced |
| `dotall` | Make `.` match newlines in regex strings |

## Conditions

### String references

```
$a                 # this string matched
#a                 # the number of matches (an integer)
```

### Set operators

```
any of them            # at least one string matched
all of them            # every string matched
2 of them              # at least two strings matched
any of ($note*)        # at least one string whose id starts with "note"
all of ($net1, $net2)  # every listed string matched
```

### Boolean logic

`and`, `or`, `not`, and parentheses. `not` binds tighter than `and`, which binds
tighter than `or`.

```
($a and $b) or not $c
```

### Numeric and comparison operators

`==`, `!=`, `<`, `<=`, `>`, `>=` work on numbers, match counts and `filesize`.

```
filesize > 5MB
#a >= 3
filesize < 1KB or #url > 10
```

Size suffixes `KB`, `MB` and `GB` are supported, as are hex literals (`0x200`).

### Reading bytes

`uint8(offset)`, `uint16(offset)`, `uint32(offset)` and `uint64(offset)` read
little-endian integers from the file, which is how you key on a header field.

```
uint16(0) == 0x5A4D          # MZ header
uint32(0x3C) > 0x40
```

`entrypoint` is accepted for compatibility and currently evaluates to 0.

## Worked examples

### High precision: a specific tool

```
rule Credential_Dumping_Tools
{
    meta:
        severity    = "critical"
        score       = 45
        description = "References credential-dumping tooling or LSASS access"

    strings:
        $a = "sekurlsa::logonpasswords" nocase
        $b = "mimikatz" nocase
        $c = "lsass.exe" nocase

    condition:
        any of them
}
```

### Behavioural combination

The condition is where the value is. Requiring two of a set trades a little
recall for a lot of precision.

```
rule SSH_Key_Harvesting
{
    meta:
        severity = "high"
        score    = 30

    strings:
        $a = ".ssh/id_rsa"
        $b = ".ssh/id_ed25519"
        $c = "/etc/shadow"
        $d = ".bash_history"

    condition:
        2 of them
}
```

### Structural

```
rule Suspicious_Overlay
{
    meta:
        severity = "low"
        score    = 10

    condition:
        filesize > 1MB and uint16(0) == 0x5A4D
}
```

## Writing good rules

**Anchor on behaviour, not names.** A string like `"malware.exe"` is brittle. A
combination of `VirtualAllocEx` and `WriteProcessMemory` describes what the
sample does and survives a rename.

**Prefer two-of-N over any-of-N for generic tokens.** Common words appear in
benign software. Requiring agreement between two independent markers removes most
of the noise.

**Set severity and score deliberately.** They are what turn a match into a
verdict. Reserve `critical` and scores above 40 for behaviour that is rarely
benign, such as shadow-copy deletion or a reverse shell.

**Use `nocase` for prose, not for API names.** `VirtualAllocEx` has a fixed
casing; case-insensitivity there only widens the false-positive surface.

**Keep packs thematic.** One file per theme (`ransomware`, `downloaders`,
`credential_persistence`) makes review and attribution easier.

## Validating and listing

```bash
rea rules check rules/     # parse every pack, report syntax errors, exit 1 on failure
rea rules list rules/      # severity, score, name and description for each rule
```

`rea rules check` belongs in CI. A rule with a broken condition should fail the
build, not silently stop matching in production.

## Current limitations

Not implemented: modules (`pe.`, `math.`), `for` loops, rule references, private
rules and `at`/`in` position constraints. `fullword` is accepted but not
enforced. If a rule uses these, `rea rules check` reports a syntax error rather
than ignoring the constraint, so the gap is always visible.

One deliberate divergence from YARA: `wide` here means *also* match the UTF-16LE
encoding, so a string with `wide` still matches its ASCII form. YARA treats
`wide` alone as wide-only. If you need wide-only behaviour, write the two rules
separately.
