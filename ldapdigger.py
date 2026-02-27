#!/usr/bin/env python3
"""
ldapdigger.py - LDAP Enumeration Tool for ForgeRock/OpenDJ
Author: @riversen
Usage: python3 ldapdigger.py -H ldap://10.82.148.32:1389 -b "dc=prd,dc=tch"
"""

import argparse
import sys
import json
import csv
import os
import re
import cmd
import time
from datetime import datetime
from collections import defaultdict

try:
    import ldap
    from ldap.controls import SimplePagedResultsControl
except ImportError:
    print("[!] python-ldap not installed. Install with: pip install python-ldap")
    print("    On Debian/Ubuntu you may also need: apt install libldap2-dev libsasl2-dev")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

INTERESTING_ATTRS = [
    # Identity
    "uid", "cn", "sn", "givenName", "displayName", "mail", "userPrincipalName",
    "sAMAccountName", "employeeNumber", "employeeID", "employeeType",
    # Contact
    "telephoneNumber", "mobile", "facsimileTelephoneNumber", "pager",
    "homePhone", "postalAddress", "street", "l", "st", "postalCode", "co",
    # Org
    "o", "ou", "title", "description", "departmentNumber", "manager",
    "businessCategory", "roomNumber", "physicalDeliveryOfficeName",
    # Account / Auth
    "userPassword", "authPassword", "userCertificate", "sshPublicKey",
    "krbPrincipalName", "memberOf", "isMemberOf",
    # Groups
    "member", "uniqueMember", "memberUid", "groupOfNames", "groupOfUniqueNames",
    # ForgeRock / OpenDJ specific
    "ds-privilege-name", "ds-pwp-password-policy-dn", "inetUserStatus",
    "inetUserHttpURL", "iplanet-am-user-alias-list",
    # Misc useful
    "labeledURI", "info", "comment", "gecos", "loginShell", "homeDirectory",
    "uidNumber", "gidNumber", "host", "authorizedService",
    # Timestamps
    "createTimestamp", "modifyTimestamp", "pwdChangedTime", "pwdLastSuccess",
]

# Common object classes worth hunting
OBJECTCLASS_SEARCHES = [
    "inetOrgPerson", "organizationalPerson", "person", "account",
    "posixAccount", "groupOfNames", "groupOfUniqueNames", "posixGroup",
    "organizationalUnit", "organization", "device", "applicationProcess",
    "serviceObject", "ds-cfg-root-dn-user",
]

# Brute-force attribute prefixes for wildcard user enumeration
ALPHA = list("abcdefghijklmnopqrstuvwxyz")
NUMERIC = list("0123456789")
# Special characters commonly found in uids/cns: dots, hyphens, underscores,
# plus signs, at signs, spaces, etc.  Some need LDAP filter escaping.
SPECIAL = list("._-+@$ !#&'~")

# Characters that must be escaped in LDAP filters (RFC 4515)
_LDAP_ESCAPE = {
    '\\': r'\5c',
    '*':  r'\2a',
    '(':  r'\28',
    ')':  r'\29',
    '\0': r'\00',
}

def ldap_escape(s):
    """Escape a string for use as a value in an LDAP filter."""
    return ''.join(_LDAP_ESCAPE.get(c, c) for c in s)

# Combined set for top-level sweeps
ALL_PREFIXES = ALPHA + NUMERIC + SPECIAL

# Page size for Simple Paged Results
PAGE_SIZE = 500

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def decode_val(val):
    """Decode bytes to string, handling binary gracefully."""
    if isinstance(val, bytes):
        try:
            return val.decode("utf-8")
        except UnicodeDecodeError:
            return val.hex()
    return str(val)


def decode_entry(entry):
    """Decode all values in an LDAP entry dict."""
    decoded = {}
    for attr, vals in entry.items():
        decoded[attr] = [decode_val(v) for v in vals]
    return decoded


def ts():
    return datetime.now().strftime("%H:%M:%S")


class LDAPEnum:
    """Core enumeration engine."""

    def __init__(self, uri, base_dn, timeout=10, page_size=PAGE_SIZE, verbose=False):
        self.uri = uri
        self.base_dn = base_dn
        self.timeout = timeout
        self.page_size = page_size
        self.verbose = verbose
        self.conn = None
        self.schema_attrs = []
        self.naming_contexts = []
        self.results = []  # list of (dn, decoded_attrs)
        self._paging_denied = False
        self._size_limited = False
        self._readable_attrs = None  # discovered via probe_readable_attrs()
        self._use_star = True        # whether "*" works for this server
        self._use_plus = True        # whether "+" (operational) works

    @property
    def request_attrs(self):
        """Return the attribute list to use in searches.
        If we've probed and found explicit attrs work better, use those.
        Otherwise fall back to ["*"] or ["*", "+"]."""
        if self._readable_attrs is not None:
            return list(self._readable_attrs)
        parts = []
        if self._use_star:
            parts.append("*")
        if self._use_plus:
            parts.append("+")
        return parts if parts else None

    # -- connection ---------------------------------------------------------

    def connect(self):
        """Establish anonymous bind."""
        print(f"[*] [{ts()}] Connecting to {self.uri} ...")
        self.conn = ldap.initialize(self.uri)
        self.conn.set_option(ldap.OPT_NETWORK_TIMEOUT, self.timeout)
        self.conn.set_option(ldap.OPT_TIMEOUT, self.timeout)
        self.conn.set_option(ldap.OPT_REFERRALS, 0)
        self.conn.protocol_version = ldap.VERSION3
        try:
            self.conn.simple_bind_s("", "")
            print(f"[+] [{ts()}] Anonymous bind successful")
            return True
        except ldap.LDAPError as e:
            print(f"[-] [{ts()}] Bind failed: {e}")
            return False

    # -- base DN discovery --------------------------------------------------

    def discover_base_dn(self):
        """Auto-discover base DN from Root DSE namingContexts.
        Queries the Root DSE for namingContexts / defaultNamingContext,
        filters out internal ForgeRock/OpenDJ contexts, and picks the
        most likely user-data context."""
        print(f"\n{'='*70}")
        print(f"[*] [{ts()}] Auto-discovering base DN from Root DSE")
        print(f"{'='*70}")

        contexts = []
        try:
            res = self.conn.search_s(
                "", ldap.SCOPE_BASE, "(objectClass=*)",
                ["namingContexts", "defaultNamingContext"]
            )
            if res:
                dn, attrs = res[0]
                decoded = decode_entry(attrs)
                # defaultNamingContext is authoritative if present
                if "defaultNamingContext" in decoded:
                    contexts.extend(decoded["defaultNamingContext"])
                if "namingContexts" in decoded:
                    contexts.extend(decoded["namingContexts"])
        except ldap.LDAPError as e:
            print(f"[-] Root DSE query failed: {e}")
            return None

        if not contexts:
            print(f"[-] No naming contexts found in Root DSE")
            return None

        # Deduplicate preserving order
        seen = set()
        unique = []
        for c in contexts:
            if c not in seen:
                seen.add(c)
                unique.append(c)

        # Filter out internal / config contexts common in ForgeRock/OpenDJ
        internal_prefixes = (
            "cn=config", "cn=schema", "cn=monitor", "cn=admin data",
            "cn=backups", "cn=tasks", "cn=ads-", "dc=replicationchanges",
            "cn=changelog", "o=cts-reaper",
        )
        user_contexts = [c for c in unique if not c.lower().startswith(internal_prefixes)]

        if not user_contexts:
            # Everything looked internal — fall back to all of them
            user_contexts = unique

        for c in user_contexts:
            print(f"  [+] Found naming context: {c}")

        if len(user_contexts) == 1:
            chosen = user_contexts[0]
        else:
            # Prefer the one with dc= components (most likely user data)
            dc_contexts = [c for c in user_contexts if "dc=" in c.lower()]
            # Or the one with o= (org)
            o_contexts = [c for c in user_contexts if "o=" in c.lower()]
            if dc_contexts:
                chosen = dc_contexts[0]
            elif o_contexts:
                chosen = o_contexts[0]
            else:
                chosen = user_contexts[0]

        print(f"  [+] Using base DN: {chosen}")
        return chosen

    def probe_readable_attrs(self):
        """Probe a sample entry to discover which attributes are actually
        returned by this server for anonymous binds.

        ForgeRock/OpenDJ often ignores '*' for anon and only returns attrs
        explicitly named in the request. We:
          1. Find a sample entry using a minimal query
          2. Try '*' — see what comes back
          3. Try '*' + explicit INTERESTING_ATTRS — see if we get more
          4. If explicit is better, use that list going forward
        """
        print(f"\n{'='*70}")
        print(f"[*] [{ts()}] Probing readable attributes")
        print(f"{'='*70}")

        # Step 1: find any one entry to probe against
        sample_dn = None
        for probe_filter in ["(uid=*)", "(cn=*)", "(objectClass=inetOrgPerson)",
                              "(objectClass=person)", "(objectClass=*)"]:
            try:
                rdata = self.conn.search_st(
                    self.base_dn, ldap.SCOPE_SUBTREE, probe_filter,
                    attrlist=["uid", "cn"],  # minimal — just find a DN
                    timeout=self.timeout,
                )
                for dn, _attrs in rdata:
                    if dn is not None:
                        sample_dn = dn
                        break
            except ldap.SIZELIMIT_EXCEEDED:
                # Partial results are fine — we just need one DN
                try:
                    rdata = self.conn.search_st(
                        self.base_dn, ldap.SCOPE_SUBTREE, probe_filter,
                        attrlist=["uid", "cn"],
                        timeout=self.timeout,
                    )
                except ldap.SIZELIMIT_EXCEEDED:
                    pass
                except ldap.LDAPError:
                    pass
            except ldap.LDAPError:
                continue
            if sample_dn:
                break

        if not sample_dn:
            print(f"[-] Could not find any entry to probe — will use explicit attr list")
            self._readable_attrs = set(INTERESTING_ATTRS + ["objectClass"])
            self._use_star = False
            self._use_plus = False
            return

        print(f"  [*] Probing against: {sample_dn}")

        # Step 2: try with just "*"
        star_attrs = set()
        try:
            rdata = self.conn.search_st(
                sample_dn, ldap.SCOPE_BASE, "(objectClass=*)",
                attrlist=["*"],
                timeout=self.timeout,
            )
            for _dn, attrs in rdata:
                star_attrs = set(k if isinstance(k, str) else k.decode() for k in attrs.keys())
        except ldap.LDAPError:
            pass
        print(f"  [*] With '*': got {len(star_attrs)} attributes: {sorted(star_attrs)[:15]}{'...' if len(star_attrs) > 15 else ''}")

        # Step 3: try with "*" + "+" (operational)
        starplus_attrs = set()
        try:
            rdata = self.conn.search_st(
                sample_dn, ldap.SCOPE_BASE, "(objectClass=*)",
                attrlist=["*", "+"],
                timeout=self.timeout,
            )
            for _dn, attrs in rdata:
                starplus_attrs = set(k if isinstance(k, str) else k.decode() for k in attrs.keys())
        except ldap.LDAPError:
            self._use_plus = False
        extra_from_plus = starplus_attrs - star_attrs
        if extra_from_plus:
            print(f"  [*] With '*','+': {len(extra_from_plus)} extra operational attrs")
        else:
            self._use_plus = False

        # Step 4: try with explicit attribute names
        explicit_attrs = set()
        # Request in chunks to avoid overly long requests
        all_to_try = list(set(INTERESTING_ATTRS + ["objectClass"]))
        try:
            rdata = self.conn.search_st(
                sample_dn, ldap.SCOPE_BASE, "(objectClass=*)",
                attrlist=all_to_try,
                timeout=self.timeout,
            )
            for _dn, attrs in rdata:
                explicit_attrs = set(k if isinstance(k, str) else k.decode() for k in attrs.keys())
        except ldap.LDAPError:
            pass
        print(f"  [*] With explicit names: got {len(explicit_attrs)} attributes: {sorted(explicit_attrs)[:15]}{'...' if len(explicit_attrs) > 15 else ''}")

        # Step 5: decide strategy
        extra_from_explicit = explicit_attrs - star_attrs
        if extra_from_explicit:
            print(f"  [+] Explicit naming returned {len(extra_from_explicit)} MORE attrs than '*'!")
            print(f"      Extra: {sorted(extra_from_explicit)}")
            print(f"  [+] Switching to explicit attribute requests")
            # Combine: everything '*' returned + everything explicit returned
            # Plus keep requesting all INTERESTING_ATTRS in case other entries have different ones
            self._readable_attrs = star_attrs | explicit_attrs | set(INTERESTING_ATTRS) | {"objectClass"}
            self._use_star = False
            self._use_plus = False
        elif star_attrs:
            print(f"  [+] '*' works fine — server returns attrs via wildcard")
            # Still include explicit names as a belt-and-suspenders approach
            # Some servers return base attrs with * but miss some unless named
            self._readable_attrs = star_attrs | set(INTERESTING_ATTRS) | {"objectClass"}
            self._use_star = False  # we'll just use the explicit list
            self._use_plus = False
        else:
            print(f"  [!] Neither '*' nor explicit naming returned attrs — very restrictive ACIs")
            self._readable_attrs = set(INTERESTING_ATTRS + ["objectClass"])
            self._use_star = False
            self._use_plus = False

        print(f"  [+] Will request {len(self._readable_attrs)} named attributes per search")

    # -- search methods -----------------------------------------------------

    def _simple_search(self, base, scope, filterstr, attrlist=None):
        """Plain search without paging controls. Handles SIZELIMIT_EXCEEDED
        gracefully by collecting partial results."""
        entries = []
        try:
            rdata = self.conn.search_st(
                base, scope, filterstr,
                attrlist=attrlist,
                timeout=self.timeout,
            )
            for dn, attrs in rdata:
                if dn is not None:
                    entries.append((dn, decode_entry(attrs)))
        except ldap.SIZELIMIT_EXCEEDED:
            # python-ldap raises this but may have already buffered partial
            # results internally.  Re-issue with search_ext + result3 to
            # drain whatever the server sent back.
            self._size_limited = True
            try:
                msgid = self.conn.search_ext(
                    base, scope, filterstr,
                    attrlist=attrlist,
                )
                # all=0 means return one result at a time
                while True:
                    try:
                        _rtype, rdata, _rmsgid, _sctrls = self.conn.result3(
                            msgid, all=0, timeout=self.timeout
                        )
                        if not rdata:
                            break
                        for dn, attrs in rdata:
                            if dn is not None:
                                entries.append((dn, decode_entry(attrs)))
                    except ldap.SIZELIMIT_EXCEEDED:
                        break
                    except ldap.LDAPError:
                        break
            except ldap.LDAPError:
                pass
            if self.verbose and entries:
                print(f"  [!] Size limit hit for {filterstr}, got {len(entries)} partial results")
        except ldap.TIMELIMIT_EXCEEDED:
            if self.verbose:
                print(f"  [!] Time limit exceeded for: {filterstr}")
        except ldap.NO_SUCH_OBJECT:
            if self.verbose:
                print(f"  [!] No such object: {base}")
        except ldap.LDAPError as e:
            if self.verbose:
                print(f"  [!] LDAP error: {e}")
        return entries

    def _paged_search(self, base, scope, filterstr, attrlist=None):
        """Search using Simple Paged Results control (OID 1.2.840.113556.1.4.319)."""
        pg_ctrl = SimplePagedResultsControl(True, size=self.page_size, cookie="")
        entries = []
        while True:
            try:
                msgid = self.conn.search_ext(
                    base, scope, filterstr,
                    attrlist=attrlist,
                    serverctrls=[pg_ctrl],
                )
                _rtype, rdata, _rmsgid, serverctrls = self.conn.result3(msgid, timeout=self.timeout)
            except ldap.SIZELIMIT_EXCEEDED:
                break
            except ldap.TIMELIMIT_EXCEEDED:
                break
            except ldap.LDAPError:
                raise

            for dn, attrs in rdata:
                if dn is not None:
                    entries.append((dn, decode_entry(attrs)))

            pctrls = [c for c in serverctrls
                      if c.controlType == SimplePagedResultsControl.controlType]
            if pctrls:
                cookie = pctrls[0].cookie
                if cookie:
                    pg_ctrl.cookie = cookie
                    continue
            break
        return entries

    def paged_search(self, base, scope, filterstr, attrlist=None):
        """Search with automatic fallback: paged → simple.

        ForgeRock/OpenDJ commonly denies the Paged Results control
        (OID 1.2.840.113556.1.4.319) for anonymous binds. When this
        happens we detect it once, flip a flag, and use plain searches
        for the rest of the session.

        If the server imposes a size limit on unpaged searches, we
        handle SIZELIMIT_EXCEEDED and collect partial results. The
        wildcard enumeration (a*, b*, …) naturally works around size
        limits by splitting the keyspace.
        """
        self._size_limited = False

        # Already know paging is denied — go straight to simple
        if self._paging_denied:
            return self._simple_search(base, scope, filterstr, attrlist)

        try:
            return self._paged_search(base, scope, filterstr, attrlist)
        except ldap.LDAPError as e:
            err_msg = str(e)
            if "1.2.840.113556.1.4.319" in err_msg or "Insufficient access" in err_msg \
               or (isinstance(e, ldap.INSUFFICIENT_ACCESS)):
                if not self._paging_denied:
                    print(f"[*] Paged Results control denied — switching to simple search mode")
                    self._paging_denied = True
                return self._simple_search(base, scope, filterstr, attrlist)
            if self.verbose:
                print(f"  [!] LDAP error: {e}")
            return []

    # -- Root DSE -----------------------------------------------------------

    def enum_root_dse(self):
        """Pull Root DSE for server info and naming contexts."""
        print(f"\n{'='*70}")
        print(f"[*] [{ts()}] Enumerating Root DSE")
        print(f"{'='*70}")
        try:
            res = self.conn.search_s("", ldap.SCOPE_BASE, "(objectClass=*)")
            if res:
                dn, attrs = res[0]
                decoded = decode_entry(attrs)
                for key, vals in sorted(decoded.items()):
                    for v in vals:
                        print(f"  {key}: {v}")
                # Capture naming contexts
                for nc_attr in ["namingContexts", "defaultNamingContext"]:
                    if nc_attr in decoded:
                        self.naming_contexts.extend(decoded[nc_attr])
                return decoded
        except ldap.LDAPError as e:
            print(f"[-] Root DSE query failed: {e}")
        return {}

    # -- Schema enumeration -------------------------------------------------

    def enum_schema(self):
        """Pull subschemaSubentry to discover attribute types."""
        print(f"\n{'='*70}")
        print(f"[*] [{ts()}] Enumerating Schema (attribute types)")
        print(f"{'='*70}")
        try:
            res = self.conn.search_s(
                "cn=schema", ldap.SCOPE_BASE, "(objectClass=*)",
                ["attributeTypes"]
            )
            if res:
                dn, attrs = res[0]
                attr_defs = attrs.get("attributeTypes", attrs.get(b"attributeTypes", []))
                names = []
                for raw in attr_defs:
                    s = decode_val(raw)
                    m = re.search(r"NAME\s+'([^']+)'", s)
                    if not m:
                        m = re.search(r"NAME\s+\(\s*'([^']+)'", s)
                    if m:
                        names.append(m.group(1))
                self.schema_attrs = sorted(set(names))
                print(f"[+] Found {len(self.schema_attrs)} attribute type definitions")
                if self.verbose:
                    for n in self.schema_attrs[:50]:
                        print(f"    {n}")
                    if len(self.schema_attrs) > 50:
                        print(f"    ... and {len(self.schema_attrs)-50} more")
                return self.schema_attrs
        except ldap.LDAPError as e:
            print(f"[-] Schema query failed (may not be exposed): {e}")
        # Fallback: try cn=subschema
        try:
            res = self.conn.search_s(
                "cn=subschema", ldap.SCOPE_BASE, "(objectClass=*)",
                ["attributeTypes"]
            )
            if res:
                print(f"[+] Found schema at cn=subschema")
        except ldap.LDAPError:
            pass
        return []

    # -- Enumerate OUs / tree structure ------------------------------------

    def enum_tree(self, base=None, depth=0, max_depth=3):
        """Recursively enumerate the directory tree structure."""
        if base is None:
            base = self.base_dn
        if depth > max_depth:
            return []

        tree = []
        try:
            entries = self.paged_search(
                base, ldap.SCOPE_ONELEVEL,
                "(|(objectClass=organizationalUnit)(objectClass=organization)"
                "(objectClass=domain)(objectClass=container))",
                ["ou", "o", "description", "objectClass"]
            )
            for dn, attrs in entries:
                indent = "  " * depth
                name = attrs.get("ou", attrs.get("o", [""]))[0] if attrs else dn
                desc = attrs.get("description", [""])[0]
                ocs = ", ".join(attrs.get("objectClass", []))
                desc_str = f" - {desc}" if desc else ""
                print(f"  {indent}├── {dn}{desc_str}  [{ocs}]")
                tree.append((dn, attrs))
                tree.extend(self.enum_tree(dn, depth + 1, max_depth))
        except ldap.LDAPError as e:
            if self.verbose:
                print(f"  {'  '*depth}[!] Error at {base}: {e}")
        return tree

    # -- Objectclass-based enumeration -------------------------------------

    def enum_by_objectclass(self):
        """Search for entries by common objectClasses, pulling all attrs."""
        print(f"\n{'='*70}")
        print(f"[*] [{ts()}] Enumerating entries by objectClass")
        print(f"{'='*70}")
        total = 0
        seen_dns = set()

        for oc in OBJECTCLASS_SEARCHES:
            entries = self.paged_search(
                self.base_dn, ldap.SCOPE_SUBTREE,
                f"(objectClass={oc})",
                attrlist=self.request_attrs
            )
            new = [(dn, attrs) for dn, attrs in entries if dn not in seen_dns]
            for dn, attrs in new:
                seen_dns.add(dn)
                self.results.append((dn, attrs))

            if new:
                print(f"  [+] objectClass={oc}: {len(new)} entries")
                total += len(new)
            elif self.verbose:
                print(f"  [-] objectClass={oc}: 0 entries")

        print(f"[+] Total unique entries from objectClass sweep: {total}")
        return total

    # -- Wildcard user enumeration -----------------------------------------

    def _wildcard_search(self, attr, prefix, seen_dns, depth=0, max_depth=3):
        """Recursive wildcard search. If a prefix hits the size limit,
        drill deeper (e.g. a* → aa*, ab*, …) to get complete results.
        Properly escapes special characters in LDAP filter values."""
        new_entries = []
        escaped = ldap_escape(prefix)
        filt = f"({attr}={escaped}*)"
        entries = self.paged_search(
            self.base_dn, ldap.SCOPE_SUBTREE,
            filt,
            attrlist=self.request_attrs
        )
        for dn, attrs in entries:
            if dn not in seen_dns:
                seen_dns.add(dn)
                new_entries.append((dn, attrs))

        # If we hit a size limit and haven't recursed too deep, split further
        if self._size_limited and depth < max_depth:
            if self.verbose:
                print(f"  [>] Size limit on {attr}={prefix}* — drilling deeper (depth {depth+1})")
            for char in ALL_PREFIXES:
                deeper = self._wildcard_search(attr, prefix + char, seen_dns, depth + 1, max_depth)
                new_entries.extend(deeper)

        return new_entries

    def enum_users_wildcard(self, attr="uid"):
        """Wildcard brute across a-z, 0-9, and special characters.
        Automatically drills deeper when server size limits truncate results."""
        print(f"\n{'='*70}")
        print(f"[*] [{ts()}] Wildcard enumeration on {attr}=<char>*")
        print(f"{'='*70}")
        seen_dns = {dn for dn, _ in self.results}
        total_new = 0

        for char in ALL_PREFIXES:
            new = self._wildcard_search(attr, char, seen_dns)
            for dn, attrs in new:
                self.results.append((dn, attrs))
            if new:
                disp = repr(char) if char in SPECIAL else char
                print(f"  [+] {attr}={disp}*: {len(new)} new entries")
                total_new += len(new)

        print(f"[+] New entries from wildcard enum: {total_new}")
        return total_new

    # -- Targeted attribute hunt -------------------------------------------

    def enum_interesting_attrs(self):
        """Search for entries that have specific interesting attributes populated."""
        print(f"\n{'='*70}")
        print(f"[*] [{ts()}] Hunting for entries with interesting attributes")
        print(f"{'='*70}")
        seen_dns = {dn for dn, _ in self.results}
        total_new = 0

        # Attributes that are worth searching for presence
        hunt_attrs = [
            "userPassword", "sshPublicKey", "description", "info", "comment",
            "manager", "memberOf", "isMemberOf", "labeledURI",
            "ds-privilege-name", "userCertificate", "krbPrincipalName",
            "authorizedService", "host",
        ]

        for attr in hunt_attrs:
            entries = self.paged_search(
                self.base_dn, ldap.SCOPE_SUBTREE,
                f"({attr}=*)",
                attrlist=self.request_attrs
            )
            new = [(dn, attrs) for dn, attrs in entries if dn not in seen_dns]
            for dn, a in new:
                seen_dns.add(dn)
                self.results.append((dn, a))
            if entries:
                print(f"  [+] {attr}=* : {len(entries)} entries ({len(new)} new)")
                total_new += len(new)

        print(f"[+] New entries from attribute hunt: {total_new}")
        return total_new

    # -- Full subtree dump -------------------------------------------------

    def enum_full_subtree(self):
        """Attempt a full subtree dump with (objectClass=*). May fail on large dirs."""
        print(f"\n{'='*70}")
        print(f"[*] [{ts()}] Attempting full subtree dump")
        print(f"{'='*70}")
        seen_dns = {dn for dn, _ in self.results}

        try:
            entries = self.paged_search(
                self.base_dn, ldap.SCOPE_SUBTREE,
                "(objectClass=*)",
                attrlist=self.request_attrs
            )
            new = [(dn, attrs) for dn, attrs in entries if dn not in seen_dns]
            for dn, attrs in new:
                seen_dns.add(dn)
                self.results.append((dn, attrs))
            print(f"[+] Full subtree: {len(entries)} total, {len(new)} new")
        except ldap.LDAPError as e:
            print(f"[-] Full subtree dump failed: {e}")
            print("    (This is common - server may limit anonymous subtree searches)")

    # -- Export -------------------------------------------------------------

    def export_ldif(self, filepath):
        """Export results in LDIF format."""
        with open(filepath, "w") as f:
            for dn, attrs in self.results:
                f.write(f"dn: {dn}\n")
                for attr, vals in sorted(attrs.items()):
                    for v in vals:
                        f.write(f"{attr}: {v}\n")
                f.write("\n")
        print(f"[+] Exported {len(self.results)} entries to {filepath}")

    def export_json(self, filepath):
        """Export results as JSON."""
        data = []
        for dn, attrs in self.results:
            entry = {"dn": dn}
            entry.update(attrs)
            data.append(entry)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Exported {len(self.results)} entries to {filepath}")

    def export_csv_users(self, filepath):
        """Export user-centric CSV with common fields."""
        fields = [
            "dn", "uid", "cn", "sn", "givenName", "displayName", "mail",
            "title", "description", "telephoneNumber", "mobile",
            "ou", "departmentNumber", "manager", "employeeNumber",
            "memberOf", "isMemberOf", "loginShell", "homeDirectory",
            "inetUserStatus", "createTimestamp", "modifyTimestamp",
        ]
        with open(filepath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for dn, attrs in self.results:
                row = {"dn": dn}
                for field in fields[1:]:
                    vals = attrs.get(field, [])
                    row[field] = "; ".join(vals) if vals else ""
                writer.writerow(row)
        print(f"[+] Exported user CSV to {filepath}")

    def export_userlist(self, filepath, attr="uid"):
        """Export a plain list of a single attribute (e.g., uid list for spraying)."""
        vals = set()
        for dn, attrs in self.results:
            for v in attrs.get(attr, []):
                if v:
                    vals.add(v)
        with open(filepath, "w") as f:
            for v in sorted(vals):
                f.write(v + "\n")
        print(f"[+] Exported {len(vals)} unique {attr} values to {filepath}")

    # -- Stats / summary ---------------------------------------------------

    def print_summary(self):
        """Print summary statistics."""
        print(f"\n{'='*70}")
        print(f"[*] ENUMERATION SUMMARY")
        print(f"{'='*70}")
        print(f"  Total entries collected: {len(self.results)}")

        # Count by objectClass
        oc_counts = defaultdict(int)
        for dn, attrs in self.results:
            for oc in attrs.get("objectClass", []):
                oc_counts[oc] += 1
        if oc_counts:
            print(f"\n  Object class distribution:")
            for oc, count in sorted(oc_counts.items(), key=lambda x: -x[1])[:20]:
                print(f"    {oc}: {count}")

        # Count populated interesting attributes
        attr_counts = defaultdict(int)
        for dn, attrs in self.results:
            for attr in INTERESTING_ATTRS:
                if attr in attrs and attrs[attr]:
                    attr_counts[attr] += 1
        if attr_counts:
            print(f"\n  Interesting attribute population:")
            for attr, count in sorted(attr_counts.items(), key=lambda x: -x[1]):
                print(f"    {attr}: {count} entries")

        # Flag high-value finds
        print(f"\n  High-value findings:")
        for attr in ["userPassword", "sshPublicKey", "userCertificate",
                      "ds-privilege-name", "description", "info", "comment",
                      "krbPrincipalName", "authorizedService"]:
            entries_with = [(dn, a) for dn, a in self.results if attr in a]
            if entries_with:
                print(f"    [!] {attr} found on {len(entries_with)} entries")
                if len(entries_with) <= 5:
                    for dn, a in entries_with:
                        print(f"        {dn}: {a[attr]}")

    # -- Run all -----------------------------------------------------------

    def run_full_enum(self):
        """Execute the full enumeration pipeline."""
        if not self.connect():
            return False

        if not self.base_dn:
            self.base_dn = self.discover_base_dn()
            if not self.base_dn:
                print("[-] Could not discover base DN. Specify with -b.")
                return False

        self.enum_root_dse()
        self.probe_readable_attrs()

        print(f"\n{'='*70}")
        print(f"[*] [{ts()}] Enumerating directory tree structure")
        print(f"{'='*70}")
        self.enum_tree()

        self.enum_schema()
        self.enum_full_subtree()
        self.enum_by_objectclass()
        self.enum_users_wildcard("uid")
        self.enum_users_wildcard("cn")
        self.enum_interesting_attrs()
        self.print_summary()
        return True


# ---------------------------------------------------------------------------
# Interactive Shell
# ---------------------------------------------------------------------------

class LDAPShell(cmd.Cmd):
    """Interactive LDAP exploration shell."""

    intro = (
        "\n╔══════════════════════════════════════════╗\n"
        "║   LDAP Interactive Explorer              ║\n"
        "║   Type 'help' for commands               ║\n"
        "╚══════════════════════════════════════════╝\n"
    )
    prompt = "ldap> "

    def __init__(self, enumerator):
        super().__init__()
        self.enum = enumerator
        if not self.enum.conn:
            self.enum.connect()

    def do_search(self, line):
        """search <filter> [base] - Run an LDAP search. Example: search (uid=admin*)"""
        parts = line.strip().split(None, 1)
        if not parts:
            print("Usage: search <filter> [base_dn]")
            return
        filt = parts[0]
        base = parts[1] if len(parts) > 1 else self.enum.base_dn
        try:
            entries = self.enum.paged_search(base, ldap.SCOPE_SUBTREE, filt, self.enum.request_attrs)
            print(f"[+] {len(entries)} results:\n")
            for dn, attrs in entries:
                print(f"dn: {dn}")
                for k, v in sorted(attrs.items()):
                    for val in v:
                        print(f"  {k}: {val}")
                print()
        except Exception as e:
            print(f"[!] Error: {e}")

    def do_read(self, line):
        """read <dn> - Read all attributes of a specific DN."""
        dn = line.strip()
        if not dn:
            print("Usage: read <dn>")
            return
        try:
            entries = self.enum.paged_search(dn, ldap.SCOPE_BASE, "(objectClass=*)", self.enum.request_attrs)
            for d, attrs in entries:
                print(f"dn: {d}")
                for k, v in sorted(attrs.items()):
                    for val in v:
                        print(f"  {k}: {val}")
        except Exception as e:
            print(f"[!] Error: {e}")

    def do_children(self, line):
        """children [dn] - List immediate children of a DN."""
        base = line.strip() or self.enum.base_dn
        try:
            entries = self.enum.paged_search(base, ldap.SCOPE_ONELEVEL, "(objectClass=*)", ["objectClass", "description"])
            print(f"[+] {len(entries)} children of {base}:\n")
            for dn, attrs in entries:
                ocs = ", ".join(attrs.get("objectClass", []))
                desc = attrs.get("description", [""])[0]
                desc_str = f" ({desc})" if desc else ""
                print(f"  {dn}  [{ocs}]{desc_str}")
        except Exception as e:
            print(f"[!] Error: {e}")

    def do_users(self, line):
        """users [filter_prefix] - List users. Optional prefix e.g. 'users adm'"""
        prefix = line.strip() or "*"
        if prefix != "*":
            prefix = f"{prefix}*"
        filt = f"(&(objectClass=inetOrgPerson)(uid={prefix}))"
        try:
            entries = self.enum.paged_search(self.enum.base_dn, ldap.SCOPE_SUBTREE, filt,
                                              ["uid", "cn", "mail", "title", "description"])
            print(f"[+] {len(entries)} users:\n")
            for dn, attrs in entries:
                uid = attrs.get("uid", ["?"])[0]
                cn = attrs.get("cn", [""])[0]
                mail = attrs.get("mail", [""])[0]
                title = attrs.get("title", [""])[0]
                desc = attrs.get("description", [""])[0]
                print(f"  {uid:20s} {cn:30s} {mail:35s} {title}")
                if desc:
                    print(f"  {'':20s} desc: {desc}")
        except Exception as e:
            print(f"[!] Error: {e}")

    def do_groups(self, line):
        """groups - List all groups."""
        filt = "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))"
        try:
            entries = self.enum.paged_search(self.enum.base_dn, ldap.SCOPE_SUBTREE, filt,
                                              ["cn", "description", "member", "uniqueMember", "memberUid"])
            print(f"[+] {len(entries)} groups:\n")
            for dn, attrs in entries:
                cn = attrs.get("cn", [""])[0]
                desc = attrs.get("description", [""])[0]
                members = attrs.get("member", []) + attrs.get("uniqueMember", []) + attrs.get("memberUid", [])
                print(f"  {dn}")
                if desc:
                    print(f"    description: {desc}")
                print(f"    members: {len(members)}")
                if len(members) <= 10:
                    for m in members:
                        print(f"      - {m}")
                print()
        except Exception as e:
            print(f"[!] Error: {e}")

    def do_find(self, line):
        """find <attribute> <value_pattern> - Find entries where attr matches. Example: find description *admin*"""
        parts = line.strip().split(None, 1)
        if len(parts) < 2:
            print("Usage: find <attribute> <value_pattern>")
            return
        attr, pattern = parts
        filt = f"({attr}={pattern})"
        try:
            entries = self.enum.paged_search(self.enum.base_dn, ldap.SCOPE_SUBTREE, filt, self.enum.request_attrs)
            print(f"[+] {len(entries)} results:\n")
            for dn, attrs in entries:
                print(f"dn: {dn}")
                for k, v in sorted(attrs.items()):
                    for val in v:
                        print(f"  {k}: {val}")
                print()
        except Exception as e:
            print(f"[!] Error: {e}")

    def do_schema(self, line):
        """schema [search_term] - Show schema attributes, optionally filtered."""
        if not self.enum.schema_attrs:
            self.enum.enum_schema()
        term = line.strip().lower()
        attrs = self.enum.schema_attrs
        if term:
            attrs = [a for a in attrs if term in a.lower()]
        print(f"[+] {len(attrs)} attributes:")
        for a in attrs:
            print(f"  {a}")

    def do_dse(self, line):
        """dse - Show Root DSE."""
        self.enum.enum_root_dse()

    def do_tree(self, line):
        """tree [depth] - Show directory tree. Default depth 3."""
        depth = int(line.strip()) if line.strip().isdigit() else 3
        self.enum.enum_tree(max_depth=depth)

    def do_dump(self, line):
        """dump <format> <filename> - Export collected results. Formats: ldif, json, csv, userlist"""
        parts = line.strip().split()
        if len(parts) < 2:
            print("Usage: dump <ldif|json|csv|userlist> <filename>")
            return
        fmt, filepath = parts[0], parts[1]
        if fmt == "ldif":
            self.enum.export_ldif(filepath)
        elif fmt == "json":
            self.enum.export_json(filepath)
        elif fmt == "csv":
            self.enum.export_csv_users(filepath)
        elif fmt == "userlist":
            self.enum.export_userlist(filepath)
        else:
            print(f"Unknown format: {fmt}")

    def do_base(self, line):
        """base [new_base_dn] - Show or change the search base DN."""
        if line.strip():
            self.enum.base_dn = line.strip()
            print(f"[+] Base DN set to: {self.enum.base_dn}")
        else:
            print(f"  Current base DN: {self.enum.base_dn}")

    def do_count(self, line):
        """count - Show count of collected entries."""
        print(f"  {len(self.enum.results)} entries collected so far.")

    def do_run(self, line):
        """run - Execute full automated enumeration pipeline."""
        self.enum.run_full_enum()

    def do_quit(self, line):
        """quit - Exit the shell."""
        print("Bye.")
        return True

    do_exit = do_quit
    do_q = do_quit


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="ldapdigger - LDAP Enumeration Tool for ForgeRock/OpenDJ (anonymous bind)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full automated enumeration with all exports
  ldapdigger.py -H ldap://10.82.148.32:1389 -b "dc=prd,dc=tch" --full

  # Interactive exploration mode
  ldapdigger.py -H ldap://10.82.148.32:1389 -b "dc=prd,dc=tch" -i

  # Quick dump: just objectclass sweep + export
  ldapdigger.py -H ldap://10.82.148.32:1389 -b "dc=prd,dc=tch" --oc-sweep -o results.json

  # Export user list for password spraying
  ldapdigger.py -H ldap://10.82.148.32:1389 -b "dc=prd,dc=tch" --full --userlist users.txt

  # Enumerate multiple hosts from a file
  ldapdigger.py -L targets.txt --full -o results.json
        """
    )

    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-H", "--uri", help="LDAP URI (e.g., ldap://host:port)")
    target.add_argument("-L", "--target-list", help="File with LDAP targets, one per line (URI, host, or host:port)")
    parser.add_argument("-b", "--base-dn", default="", help="Base DN (e.g., dc=prd,dc=tch). Auto-discovered from Root DSE if omitted.")
    parser.add_argument("-i", "--interactive", action="store_true", help="Launch interactive shell (single target only)")
    parser.add_argument("--full", action="store_true", help="Run full enumeration pipeline")
    parser.add_argument("--oc-sweep", action="store_true", help="Run objectClass sweep only")
    parser.add_argument("--wildcard", action="store_true", help="Run wildcard uid enumeration")
    parser.add_argument("--dump-tree", action="store_true", help="Dump directory tree structure")
    parser.add_argument("--page-size", type=int, default=PAGE_SIZE, help=f"Page size (default {PAGE_SIZE})")
    parser.add_argument("-p", "--port", type=int, default=389, help="Default port for bare hostnames in target list (default: 389)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="LDAP timeout in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    # Output options
    parser.add_argument("-o", "--output", help="Output file (auto-detect format from extension: .json, .ldif, .csv)")
    parser.add_argument("--userlist", help="Export plain uid list to file")
    parser.add_argument("--ldif", help="Export LDIF to file")
    parser.add_argument("--json", help="Export JSON to file")
    parser.add_argument("--csv", help="Export CSV to file")

    args = parser.parse_args()

    # --- Build target list ---
    if args.target_list:
        if args.interactive:
            print("[-] Interactive mode (-i) is not supported with --target-list")
            sys.exit(1)
        targets = _parse_target_list(args.target_list, args.port)
        if not targets:
            print(f"[-] No valid targets found in {args.target_list}")
            sys.exit(1)
    else:
        targets = [args.uri]

    # --- Run against each target ---
    total = len(targets)
    for idx, uri in enumerate(targets, 1):
        if total > 1:
            print(f"\n{'#'*70}")
            print(f"# TARGET {idx}/{total}: {uri}")
            print(f"{'#'*70}")

        # For multi-host runs, tag output files with a host label
        host_label = _host_label(uri) if total > 1 else None

        _run_target(args, uri, host_label)


def _parse_target_list(filepath, default_port=389):
    """Parse a target list file. Accepts URIs, host:port, or bare hosts."""
    targets = []
    try:
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Already a full URI
                if line.startswith("ldap://") or line.startswith("ldaps://"):
                    targets.append(line)
                # host:port
                elif ":" in line:
                    targets.append(f"ldap://{line}")
                # bare host — use default port
                else:
                    targets.append(f"ldap://{line}:{default_port}")
    except FileNotFoundError:
        print(f"[-] Target list not found: {filepath}")
    return targets


def _host_label(uri):
    """Extract a filesystem-safe label from a URI for output filenames."""
    label = uri.replace("ldap://", "").replace("ldaps://", "")
    label = label.replace(":", "_").replace("/", "")
    return label


def _tagged_path(filepath, label):
    """Insert a host label into a filename: results.json → results_10.10.10.1_389.json"""
    if not label or not filepath:
        return filepath
    base, ext = os.path.splitext(filepath)
    return f"{base}_{label}{ext}"


def _run_target(args, uri, host_label=None):
    """Run enumeration against a single target."""
    enum = LDAPEnum(
        uri=uri,
        base_dn=args.base_dn,
        timeout=args.timeout,
        page_size=args.page_size,
        verbose=args.verbose,
    )

    if args.interactive:
        if not enum.connect():
            sys.exit(1)
        if not enum.base_dn:
            enum.base_dn = enum.discover_base_dn()
            if not enum.base_dn:
                print("[-] Could not discover base DN. Specify with -b.")
                sys.exit(1)
        enum.probe_readable_attrs()
        shell = LDAPShell(enum)
        shell.cmdloop()
    elif args.full:
        if not enum.run_full_enum():
            if host_label:
                print(f"[-] Failed: {uri} — skipping")
                return
            sys.exit(1)
    else:
        if not enum.connect():
            if host_label:
                print(f"[-] Failed to connect: {uri} — skipping")
                return
            sys.exit(1)

        if not enum.base_dn:
            enum.base_dn = enum.discover_base_dn()
            if not enum.base_dn:
                print("[-] Could not discover base DN. Specify with -b.")
                if host_label:
                    return
                sys.exit(1)

        enum.enum_root_dse()
        enum.probe_readable_attrs()

        if args.dump_tree:
            print(f"\n{'='*70}")
            print(f"[*] [{ts()}] Directory tree structure")
            print(f"{'='*70}")
            enum.enum_tree()

        if args.oc_sweep:
            enum.enum_by_objectclass()

        if args.wildcard:
            enum.enum_users_wildcard("uid")
            enum.enum_users_wildcard("cn")

        if not args.oc_sweep and not args.wildcard and not args.dump_tree:
            print("\n[*] No enumeration flags specified. Use --full, --oc-sweep, --wildcard, or -i")
            print("    Run with -h for help.")
            if not host_label:
                sys.exit(0)
            return

        enum.print_summary()

    # --- Export ---
    if args.output:
        out = _tagged_path(args.output, host_label)
        ext = os.path.splitext(out)[1].lower()
        if ext == ".json":
            enum.export_json(out)
        elif ext == ".ldif":
            enum.export_ldif(out)
        elif ext == ".csv":
            enum.export_csv_users(out)
        else:
            enum.export_json(out)

    if args.ldif:
        enum.export_ldif(_tagged_path(args.ldif, host_label))
    if args.json:
        enum.export_json(_tagged_path(args.json, host_label))
    if args.csv:
        enum.export_csv_users(_tagged_path(args.csv, host_label))
    if args.userlist:
        enum.export_userlist(_tagged_path(args.userlist, host_label))


if __name__ == "__main__":
    main()
