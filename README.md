# ldapdigger

LDAP enumeration tool built for anonymous-bind enumeration against **ForgeRock / OpenDJ** directory servers. Also works against other LDAPv3 implementations, but the workarounds and heuristics are tuned for ForgeRock's quirks.

## ⚠️ Disclaimer

- **Authorized use only.** Only run this against systems you have explicit written permission to test.
- **Use at your own risk.** No warranties, no guarantees, no liability.
- This tool was vibe coded with [Claude](https://claude.ai) by [@riversen](https://github.com/riversen).

---

## What it does

Comprehensive LDAP enumeration designed to extract as much data as possible from an anonymously-accessible directory. Handles several ForgeRock-specific issues that break generic tools:

- **Paged Results control denied** — ForgeRock commonly blocks the Simple Paged Results control (OID `1.2.840.113556.1.4.319`) for anonymous binds. The tool detects this on the first query and automatically falls back to unpaged searches for the rest of the session.
- **`*` wildcard doesn't return attributes** — ForgeRock with restrictive ACIs often ignores the `*` return-all-attributes request for anonymous binds, silently returning only RDN attributes. The tool probes a sample entry to detect this and switches to explicitly naming every attribute it wants.
- **Server size limits** — Without paging, servers often cap results (e.g., 1000 per query). The wildcard enumeration automatically drills deeper (`a*` → `aa*`, `ab*`, …) when it detects truncated results.
- **Base DN discovery** — Automatically discovers the base DN from the Root DSE `namingContexts` if you don't provide one, filtering out internal ForgeRock contexts (`cn=config`, `cn=schema`, etc.).

### Enumeration pipeline (`--full`)

1. **Root DSE** — Server info, vendor, naming contexts
2. **Attribute probing** — Discovers which attributes are actually readable by anonymous binds
3. **Directory tree mapping** — Recursive OU/container walk
4. **Schema enumeration** — Discovers all attribute type definitions
5. **Full subtree dump** — Attempts `(objectClass=*)` with collected attribute list
6. **ObjectClass sweep** — Searches by common objectClasses (inetOrgPerson, posixAccount, groups, etc.)
7. **Wildcard brute-force** — `uid` and `cn` wildcards across `a-z`, `0-9`, and special characters (`. _ - + @ $ ! # & ' ~` and space), with RFC 4515 filter escaping and adaptive depth
8. **Interesting attribute hunt** — Searches for entries with high-value fields populated (`userPassword`, `sshPublicKey`, `description`, `info`, `ds-privilege-name`, etc.)
9. **Summary** — Object class distribution, attribute population stats, high-value findings flagged

## Installation

```bash
# Dependencies
sudo apt install -y libldap2-dev libsasl2-dev
python3 -m pip install python-ldap

# Make executable
chmod +x ldapdigger.py
```

## Usage

### Full automated enumeration

```bash
# Base DN auto-discovered
./ldapdigger.py -H ldap://10.10.10.1:389 --full -v -o loot.json

# Explicit base DN
./ldapdigger.py -H ldap://10.10.10.1:1389 -b "dc=corp,dc=local" --full -o loot.json

# All export formats at once
./ldapdigger.py -H ldap://10.10.10.1:389 --full \
  -o results.json \
  --ldif full_dump.ldif \
  --csv users.csv \
  --userlist uids.txt
```

### Interactive shell

```bash
./ldapdigger.py -H ldap://10.10.10.1:389 -i
```

Interactive commands:

| Command | Description |
|---------|-------------|
| `search <filter> [base]` | Raw LDAP filter search, e.g. `search (uid=admin*)` |
| `read <dn>` | Dump all attributes on a specific DN |
| `children [dn]` | List immediate children of a DN |
| `users [prefix]` | Quick user listing, e.g. `users adm` |
| `groups` | Enumerate all groups with membership |
| `find <attr> <pattern>` | Hunt for values, e.g. `find description *password*` |
| `tree [depth]` | Show directory tree structure |
| `schema [term]` | Browse schema attribute types |
| `dse` | Show Root DSE |
| `base [new_dn]` | Show or change search base |
| `run` | Execute full automated pipeline |
| `dump <fmt> <file>` | Export: `dump json results.json` |
| `count` | Show collected entry count |
| `quit` | Exit |

### Individual operations

```bash
# ObjectClass sweep only
./ldapdigger.py -H ldap://10.10.10.1:389 --oc-sweep -o results.json

# Wildcard enumeration only
./ldapdigger.py -H ldap://10.10.10.1:389 --wildcard -o results.json

# Tree structure only
./ldapdigger.py -H ldap://10.10.10.1:389 --dump-tree
```

### Flags reference

| Flag | Description |
|------|-------------|
| `-H`, `--uri` | LDAP URI (required), e.g. `ldap://host:port` |
| `-b`, `--base-dn` | Base DN. Auto-discovered if omitted |
| `-i`, `--interactive` | Launch interactive shell |
| `--full` | Run full enumeration pipeline |
| `--oc-sweep` | ObjectClass sweep only |
| `--wildcard` | Wildcard uid/cn enumeration only |
| `--dump-tree` | Directory tree structure only |
| `-v`, `--verbose` | Verbose output |
| `-t`, `--timeout` | LDAP timeout in seconds (default: 10) |
| `--page-size` | Paged results page size (default: 500) |
| `-o`, `--output` | Output file (format from extension: `.json`, `.ldif`, `.csv`) |
| `--json` | Export JSON to file |
| `--ldif` | Export LDIF to file |
| `--csv` | Export user-centric CSV |
| `--userlist` | Export plain uid list (one per line) |

## Companion: ldapdigger_view.py

Standalone terminal viewer for the JSON output. No dependencies beyond Python 3.

```bash
# Browse with color
./ldapdigger_view.py loot.json | less -R

# Entries with "password" anywhere
./ldapdigger_view.py loot.json -s password

# Only entries with description, show specific fields
./ldapdigger_view.py loot.json -f description -a uid,description

# Attribute population stats
./ldapdigger_view.py loot.json --stats

# Dump unique emails for a list
./ldapdigger_view.py loot.json --dump mail > emails.txt
```

## Why not ldapdomaindump / other tools?

`ldapdomaindump` and most LDAP enumeration tools are built for **Active Directory**. They expect AD-specific attributes (`sAMAccountName`, `userAccountControl`, `servicePrincipalName`, etc.) and AD schema structure. Against ForgeRock/OpenDJ they'll either error out or produce mostly empty output.

ldapdigger handles ForgeRock's specific access control behavior, attribute return quirks, and paging restrictions that AD-focused tools don't account for.

## License

Do whatever you want with it.
