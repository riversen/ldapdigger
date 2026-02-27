#!/usr/bin/env python3
"""
ldapdigger_view.py - Terminal viewer for ldapdigger JSON output
Usage:
  ./ldapdigger_view.py results.json                     # browse all entries
  ./ldapdigger_view.py results.json -f description       # only entries with description
  ./ldapdigger_view.py results.json -s admin             # grep for 'admin' across all values
  ./ldapdigger_view.py results.json -a uid,mail,description  # show only these attrs
  ./ldapdigger_view.py results.json --stats              # attribute population stats
  ./ldapdigger_view.py results.json --dump uid           # unique values of one attr
"""

import argparse
import json
import sys
import os

# ANSI colors (respects NO_COLOR)
if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
    C_DN = C_ATTR = C_VAL = C_HIT = C_DIM = C_RST = ""
else:
    C_DN   = "\033[1;36m"   # bold cyan
    C_ATTR = "\033[1;33m"   # bold yellow
    C_VAL  = "\033[0m"      # default
    C_HIT  = "\033[1;31m"   # bold red (search hits)
    C_DIM  = "\033[2m"      # dim
    C_RST  = "\033[0m"


def highlight(text, term):
    """Case-insensitive highlight of search term in text."""
    if not term:
        return text
    lower = text.lower()
    tl = term.lower()
    out, i = [], 0
    while i < len(text):
        pos = lower.find(tl, i)
        if pos == -1:
            out.append(text[i:])
            break
        out.append(text[i:pos])
        out.append(f"{C_HIT}{text[pos:pos+len(tl)]}{C_VAL}")
        i = pos + len(tl)
    return "".join(out)


def print_entry(entry, search=None, attrs_filter=None):
    dn = entry.get("dn", "???")
    print(f"{C_DN}dn: {dn}{C_RST}")
    for key, vals in sorted(entry.items()):
        if key == "dn":
            continue
        if attrs_filter and key not in attrs_filter:
            continue
        if isinstance(vals, list):
            for v in vals:
                val_str = highlight(v, search) if search else v
                print(f"  {C_ATTR}{key}{C_RST}: {val_str}")
        else:
            val_str = highlight(str(vals), search) if search else str(vals)
            print(f"  {C_ATTR}{key}{C_RST}: {val_str}")
    print()


def entry_matches(entry, search):
    """Check if any value in entry contains the search term."""
    sl = search.lower()
    for key, vals in entry.items():
        if sl in key.lower():
            return True
        if isinstance(vals, list):
            for v in vals:
                if sl in str(v).lower():
                    return True
        elif sl in str(vals).lower():
            return True
    return False


def print_stats(data):
    """Show attribute population statistics."""
    from collections import Counter
    attr_count = Counter()
    for entry in data:
        for key, vals in entry.items():
            if key == "dn":
                continue
            if isinstance(vals, list) and vals:
                attr_count[key] += 1
            elif vals:
                attr_count[key] += 1

    print(f"\n{C_DN}Attribute population across {len(data)} entries:{C_RST}\n")
    for attr, count in attr_count.most_common():
        pct = count / len(data) * 100
        bar = "█" * int(pct / 2)
        print(f"  {C_ATTR}{attr:40s}{C_RST} {count:5d} ({pct:5.1f}%) {C_DIM}{bar}{C_RST}")


def dump_attr(data, attr):
    """Print sorted unique values of a single attribute."""
    vals = set()
    for entry in data:
        v = entry.get(attr, [])
        if isinstance(v, list):
            vals.update(v)
        elif v:
            vals.add(str(v))
    for v in sorted(vals):
        print(v)
    print(f"\n{C_DIM}({len(vals)} unique values){C_RST}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description="View ldapdigger JSON output")
    ap.add_argument("file", help="JSON file from ldap_enum.py")
    ap.add_argument("-s", "--search", help="Filter entries containing this string (case-insensitive)")
    ap.add_argument("-f", "--has-attr", help="Only show entries that have this attribute populated")
    ap.add_argument("-a", "--attrs", help="Comma-separated list of attrs to display")
    ap.add_argument("--stats", action="store_true", help="Show attribute population stats")
    ap.add_argument("--dump", metavar="ATTR", help="Dump unique values of one attribute (pipe-friendly)")
    args = ap.parse_args()

    with open(args.file) as f:
        data = json.load(f)

    if not isinstance(data, list):
        print("Expected a JSON array of entries", file=sys.stderr)
        sys.exit(1)

    print(f"{C_DIM}Loaded {len(data)} entries{C_RST}\n", file=sys.stderr)

    if args.stats:
        print_stats(data)
        return

    if args.dump:
        dump_attr(data, args.dump)
        return

    attrs_filter = set(args.attrs.split(",")) if args.attrs else None
    shown = 0

    for entry in data:
        if args.has_attr:
            v = entry.get(args.has_attr, [])
            if not v or v == [""]:
                continue
        if args.search and not entry_matches(entry, args.search):
            continue
        print_entry(entry, search=args.search, attrs_filter=attrs_filter)
        shown += 1

    print(f"{C_DIM}Displayed {shown}/{len(data)} entries{C_RST}", file=sys.stderr)


if __name__ == "__main__":
    main()
