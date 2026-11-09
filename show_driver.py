#!/usr/bin/env python3
"""
Show full details of a specific driver installed in an offline Windows image.

Looks up a driver by name (service name, OEM INF, package name, or
substring match against any of those) and prints everything the image
knows about it: INF metadata, service registry, hardware IDs, DriverStore
file listing, DriverPackages metadata, and PnpLockdownFiles entry.

Designed as a companion to list_drivers.py (which gives the overview)
and inject_driver.py (which creates these entries).

Usage:
    python3 show_driver.py --image /path/to/disk.qcow2 --name viostor
    python3 show_driver.py --image /path/to/disk.qcow2 --name oem4.inf
    python3 show_driver.py --image /path/to/disk.qcow2 --name vmxnet3
    python3 show_driver.py --image /path/to/disk.qcow2 --name pvscsi --json
"""

import argparse
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

try:
    import hivex
except ImportError:
    print("ERROR: python3-hivex not installed")
    print("Install with: sudo dnf install python3-hivex")
    sys.exit(1)


# ---------------------------------------------------------------------------
# guestfish helpers
# ---------------------------------------------------------------------------

def guestfish_ro(image_path, commands):
    """Run guestfish commands read-only against the image."""
    cmd = f"run\n{commands}\n"
    return subprocess.run(
        ['guestfish', '--ro', '-a', str(image_path)],
        input=cmd, text=True, capture_output=True,
    )


def find_windows_partition(image_path):
    """Probe each partition for Windows\\System32\\config\\SOFTWARE."""
    result = guestfish_ro(image_path, "list-filesystems")
    if result.returncode != 0:
        raise RuntimeError(f"list-filesystems failed: {result.stderr}")
    partitions = [
        line.split(':')[0].strip()
        for line in result.stdout.splitlines() if line.strip()
    ]
    for part in partitions:
        check = guestfish_ro(
            image_path,
            f"mount-ro {part} /\nis-file /Windows/System32/config/SOFTWARE\n",
        )
        if check.returncode == 0 and check.stdout.strip().splitlines()[-1] == 'true':
            return part
    raise RuntimeError(f"No Windows partition found among: {partitions}")


def download_file(image_path, partition, remote_path, local_path):
    result = guestfish_ro(
        image_path,
        f"mount-ro {partition} /\ndownload {remote_path} {local_path}\n",
    )
    if result.returncode != 0:
        raise RuntimeError(f"Failed to download {remote_path}: {result.stderr}")


def download_file_optional(image_path, partition, remote_path, local_path):
    """Download a file, returning False (not raising) if it doesn't exist."""
    result = guestfish_ro(
        image_path,
        f"mount-ro {partition} /\ndownload {remote_path} {local_path}\n",
    )
    return result.returncode == 0


def list_directory(image_path, partition, remote_dir):
    """List files in a directory inside the image. Returns list of names or []."""
    result = guestfish_ro(
        image_path,
        f"mount-ro {partition} /\nls {remote_dir}\n",
    )
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def stat_file(image_path, partition, remote_path):
    """Get file size. Returns size in bytes or None."""
    result = guestfish_ro(
        image_path,
        f"mount-ro {partition} /\nfilesize {remote_path}\n",
    )
    if result.returncode != 0:
        return None
    try:
        return int(result.stdout.strip())
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# hivex helpers
# ---------------------------------------------------------------------------

def read_value(h, node, name, default=None):
    try:
        val = h.node_get_value(node, name)
    except Exception:
        return default
    vtype, _ = h.value_type(val)
    if vtype in (1, 2):
        return h.value_string(val)
    if vtype == 4:
        return h.value_dword(val)
    if vtype == 7:
        return h.value_multiple_strings(val)
    if vtype == 3:
        return h.value_value(val)[1] if isinstance(h.value_value(val), tuple) else h.value_value(val)
    return default


def read_value_typed(h, node, name):
    """Return (type_id, value) or (None, None)."""
    try:
        val = h.node_get_value(node, name)
    except Exception:
        return None, None
    vtype, _ = h.value_type(val)
    if vtype in (1, 2):
        return vtype, h.value_string(val)
    if vtype == 4:
        return vtype, h.value_dword(val)
    if vtype == 7:
        return vtype, h.value_multiple_strings(val)
    if vtype == 3:
        raw = h.value_value(val)
        return vtype, (raw[1] if isinstance(raw, tuple) else raw)
    if vtype == 0:
        return vtype, None
    return vtype, None


def safe_child(h, node, name):
    try:
        return h.node_get_child(node, name)
    except Exception:
        return None


def walk_children(h, node):
    try:
        children = h.node_children(node)
    except Exception:
        return
    for child in children:
        try:
            yield h.node_name(child), child
        except Exception:
            continue


def dump_all_values(h, node):
    """Return dict of all values at a node: {name: (type_id, value)}."""
    result = {}
    try:
        for val in h.node_values(node):
            name = h.value_key(val)
            vtype, _ = h.value_type(val)
            if vtype in (1, 2):
                result[name] = (vtype, h.value_string(val))
            elif vtype == 4:
                result[name] = (vtype, h.value_dword(val))
            elif vtype == 7:
                result[name] = (vtype, h.value_multiple_strings(val))
            elif vtype == 3:
                raw = h.value_value(val)
                result[name] = (vtype, raw[1] if isinstance(raw, tuple) else raw)
            elif vtype == 0:
                result[name] = (vtype, None)
            else:
                result[name] = (vtype, None)
    except Exception:
        pass
    return result


REG_TYPE_NAMES = {
    0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY",
    4: "REG_DWORD", 7: "REG_MULTI_SZ",
}

START_TYPES = {0: "Boot", 1: "System", 2: "Auto", 3: "Demand", 4: "Disabled"}


# ---------------------------------------------------------------------------
# INF parser (lightweight, same as list_drivers.py)
# ---------------------------------------------------------------------------

def parse_inf_full(inf_path):
    """Parse an INF file for full metadata."""
    try:
        with open(inf_path, 'rb') as f:
            raw = f.read()
    except OSError:
        return None

    content = None
    if raw.startswith(b'\xff\xfe'):
        content = raw.decode('utf-16-le')
    elif raw.startswith(b'\xfe\xff'):
        content = raw.decode('utf-16-be')
    else:
        for encoding in ['utf-8', 'latin-1']:
            try:
                content = raw.decode(encoding)
                break
            except (UnicodeDecodeError, UnicodeError):
                continue
    if content is None:
        return None

    # Parse [Strings] for token resolution
    strings = {}
    in_strings = False
    for line in content.split('\n'):
        line = line.rstrip('\r').strip()
        if line.startswith('['):
            in_strings = line.lower().strip('[]').strip() == 'strings'
            continue
        if in_strings and '=' in line:
            key, _, val = line.partition('=')
            strings[key.strip().lower()] = val.strip().strip('"')

    def resolve(s):
        if not s:
            return s
        m = re.match(r'^%(.+)%$', s.strip())
        if m:
            return strings.get(m.group(1).lower(), s)
        return s

    def strip_comment(line):
        pos = -1
        in_q = False
        for i, ch in enumerate(line):
            if ch == '"':
                in_q = not in_q
            elif ch == ';' and not in_q:
                pos = i
                break
        return line[:pos].strip() if pos >= 0 else line

    # Parse [Version] and [Manufacturer]
    current_section = None
    result = {
        'class': '', 'class_guid': '', 'provider': '', 'manufacturer': '',
        'driver_ver': '', 'catalog_file': '', 'pnp_lockdown': '',
        'driver_date': '', 'driver_version': '',
    }
    for line in content.split('\n'):
        line = line.rstrip('\r').strip()
        if line.startswith('['):
            current_section = line.lower().strip('[]').strip()
            continue

        if current_section == 'version' and '=' in line:
            line = strip_comment(line)
            key, _, val = line.partition('=')
            key = key.strip().lower()
            val = val.strip().strip('"')
            if key == 'class':
                result['class'] = val
            elif key == 'classguid':
                result['class_guid'] = val
            elif key == 'provider':
                result['provider'] = resolve(val)
            elif key == 'driverver':
                result['driver_ver'] = val
                # Split into date and version parts
                if ',' in val:
                    date_part, _, ver_part = val.partition(',')
                    result['driver_date'] = date_part.strip()
                    result['driver_version'] = ver_part.strip()
            elif key == 'catalogfile':
                result['catalog_file'] = val
            elif key == 'pnplockdown':
                result['pnp_lockdown'] = val

        elif current_section == 'manufacturer' and '=' in line:
            key, _, _ = line.partition('=')
            mfr = resolve(key.strip().strip('"'))
            if mfr and not result['manufacturer']:
                result['manufacturer'] = mfr

    return result


# ---------------------------------------------------------------------------
# Build the driver index (scan all OEM drivers to find the one we want)
# ---------------------------------------------------------------------------

def build_oem_index(system_hive, drivers_hive=None):
    """
    Build an index of all OEM drivers from registry hives.

    Returns dict keyed by oem_inf (lowercase):
    {
        "oem0.inf": {
            "package": "...",
            "configurations": [...],
            "hardware_ids": [...],
            "service": {...} or None,
        },
        ...
    }
    """
    index = {}

    for hive_path, label in [(system_hive, "SYSTEM"), (drivers_hive, "DRIVERS")]:
        if hive_path is None or not os.path.exists(hive_path):
            continue

        h = hivex.Hivex(hive_path)
        root = h.root()

        driverdb = safe_child(h, root, "DriverDatabase")
        if driverdb is not None:
            # DriverInfFiles
            inffiles = safe_child(h, driverdb, "DriverInfFiles")
            if inffiles:
                for name, child in walk_children(h, inffiles):
                    if not re.match(r'oem\d+\.inf$', name, re.IGNORECASE):
                        continue
                    key = name.lower()
                    if key not in index:
                        index[key] = {
                            "package": "", "configurations": [],
                            "hardware_ids": set(), "service": None,
                        }
                    active = read_value(h, child, "Active")
                    if active:
                        index[key]["package"] = active
                    elif not index[key]["package"]:
                        packages = read_value(h, child, "")
                        if isinstance(packages, list) and packages:
                            index[key]["package"] = packages[0]
                    configs = read_value(h, child, "Configurations")
                    if isinstance(configs, list) and configs:
                        index[key]["configurations"] = configs

            # DeviceIds -> hardware ID reverse map
            deviceids = safe_child(h, driverdb, "DeviceIds")
            if deviceids:
                def _walk(node, prefix=""):
                    for name, child in walk_children(h, node):
                        path = f"{prefix}\\{name}" if prefix else name
                        try:
                            for val in h.node_values(child):
                                val_name = h.value_key(val)
                                if re.match(r'oem\d+\.inf$', val_name, re.IGNORECASE):
                                    oem = val_name.lower()
                                    if oem not in index:
                                        index[oem] = {
                                            "package": "", "configurations": [],
                                            "hardware_ids": set(), "service": None,
                                        }
                                    if not path.startswith('{'):
                                        index[oem]["hardware_ids"].add(path)
                        except Exception:
                            pass
                        _walk(child, path)
                _walk(deviceids)

        # Services with OEM Owners
        cs001 = safe_child(h, root, "ControlSet001")
        if cs001:
            services = safe_child(h, cs001, "Services")
            if services:
                for svc_name, svc_node in walk_children(h, services):
                    owners = read_value(h, svc_node, "Owners")
                    if owners is None:
                        continue
                    if isinstance(owners, str):
                        owners = [owners]
                    for owner in owners:
                        if re.match(r'oem\d+\.inf$', owner, re.IGNORECASE):
                            oem = owner.lower()
                            if oem not in index:
                                index[oem] = {
                                    "package": "", "configurations": [],
                                    "hardware_ids": set(), "service": None,
                                }
                            start_val = read_value(h, svc_node, "Start")
                            index[oem]["service"] = {
                                "name": svc_name,
                                "start": start_val,
                                "start_type": START_TYPES.get(start_val, f"Unknown({start_val})"),
                            }

    # Convert sets to sorted lists
    for entry in index.values():
        entry["hardware_ids"] = sorted(entry["hardware_ids"])

    return index


def find_driver(index, search_term):
    """
    Find a driver by name. Matches against:
    1. Exact OEM INF name (oem4.inf)
    2. Service name (viostor)
    3. Package name prefix (viostor.inf_amd64_...)
    4. Substring match against any of the above

    Returns the oem_inf key or None.
    """
    term = search_term.lower().strip()

    # 1. Exact OEM INF match
    if term in index:
        return term
    if not term.endswith('.inf'):
        candidate = term + '.inf'
        if candidate in index:
            return candidate

    # 2. Exact service name match
    for oem, entry in index.items():
        if entry["service"] and entry["service"]["name"].lower() == term:
            return oem

    # 3. Package name prefix match (e.g. "viostor" matches "viostor.inf_amd64_...")
    for oem, entry in index.items():
        pkg = entry.get("package", "").lower()
        if pkg and pkg.startswith(term):
            return oem
        # Also match against the inf stem in the package name
        if pkg and '.' in pkg:
            inf_stem = pkg.split('.')[0]
            if inf_stem == term:
                return oem

    # 4. Substring match (last resort)
    matches = []
    for oem, entry in index.items():
        pkg = entry.get("package", "").lower()
        svc = entry["service"]["name"].lower() if entry["service"] else ""
        if term in oem or term in pkg or term in svc:
            matches.append(oem)

    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        print(f"Ambiguous search term '{search_term}' matches {len(matches)} drivers:")
        for m in sorted(matches, key=lambda n: int(re.search(r'\d+', n).group())):
            entry = index[m]
            pkg = entry.get("package", "")
            svc = entry["service"]["name"] if entry["service"] else "—"
            print(f"  {m}  package={pkg}  service={svc}")
        print(f"\nPlease be more specific.")
        return None

    return None


# ---------------------------------------------------------------------------
# Deep registry inspection for a specific driver
# ---------------------------------------------------------------------------

def get_service_details(hive_path, service_name):
    """Read the full Services\\{name} subtree."""
    h = hivex.Hivex(hive_path)
    root = h.root()
    cs001 = safe_child(h, root, "ControlSet001")
    if not cs001:
        return None
    services = safe_child(h, cs001, "Services")
    if not services:
        return None
    svc_node = safe_child(h, services, service_name)
    if not svc_node:
        return None

    result = {"values": {}, "subkeys": {}}

    # Top-level values
    for name, (vtype, val) in dump_all_values(h, svc_node).items():
        result["values"][name or "(Default)"] = {
            "type": REG_TYPE_NAMES.get(vtype, f"type({vtype})"),
            "value": _format_value(vtype, val),
        }

    # Subkeys (Parameters, Parameters\PnpInterface, etc.)
    def _walk_subkeys(node, depth=0):
        subs = {}
        for child_name, child_node in walk_children(h, node):
            entry = {"values": {}, "subkeys": {}}
            for name, (vtype, val) in dump_all_values(h, child_node).items():
                entry["values"][name or "(Default)"] = {
                    "type": REG_TYPE_NAMES.get(vtype, f"type({vtype})"),
                    "value": _format_value(vtype, val),
                }
            if depth < 3:
                entry["subkeys"] = _walk_subkeys(child_node, depth + 1)
            subs[child_name] = entry
        return subs

    result["subkeys"] = _walk_subkeys(svc_node)
    return result


def get_driverpackage_details(hive_path, package_dir):
    """Read DriverDatabase\\DriverPackages\\{package_dir} subtree."""
    h = hivex.Hivex(hive_path)
    root = h.root()
    driverdb = safe_child(h, root, "DriverDatabase")
    if not driverdb:
        return None
    packages = safe_child(h, driverdb, "DriverPackages")
    if not packages:
        return None
    pkg_node = safe_child(h, packages, package_dir)
    if not pkg_node:
        return None

    result = {"values": {}, "subkeys": {}}
    for name, (vtype, val) in dump_all_values(h, pkg_node).items():
        result["values"][name or "(Default)"] = {
            "type": REG_TYPE_NAMES.get(vtype, f"type({vtype})"),
            "value": _format_value(vtype, val),
        }

    def _walk(node, depth=0):
        subs = {}
        for child_name, child_node in walk_children(h, node):
            entry = {"values": {}, "subkeys": {}}
            for name, (vtype, val) in dump_all_values(h, child_node).items():
                entry["values"][name or "(Default)"] = {
                    "type": REG_TYPE_NAMES.get(vtype, f"type({vtype})"),
                    "value": _format_value(vtype, val),
                }
            if depth < 5:
                entry["subkeys"] = _walk(child_node, depth + 1)
            subs[child_name] = entry
        return subs

    result["subkeys"] = _walk(pkg_node)
    return result


def get_pnplockdown_entry(software_hive, driver_name):
    """Check PnpLockdownFiles for this driver."""
    h = hivex.Hivex(software_hive)
    root = h.root()
    lockdown = root
    for part in ['Microsoft', 'Windows', 'CurrentVersion', 'Setup', 'PnpLockdownFiles']:
        lockdown = safe_child(h, lockdown, part)
        if lockdown is None:
            return None

    # Look for %SystemRoot%/System32/drivers/{name}.sys
    target_key = f"%SystemRoot%/System32/drivers/{driver_name}.sys"
    entry_node = safe_child(h, lockdown, target_key)
    if entry_node is None:
        return None

    result = {}
    for name, (vtype, val) in dump_all_values(h, entry_node).items():
        result[name or "(Default)"] = {
            "type": REG_TYPE_NAMES.get(vtype, f"type({vtype})"),
            "value": _format_value(vtype, val),
        }
    return result


def get_device_id_entries(hive_path, oem_inf):
    """Get all DeviceIds entries for this OEM INF with their priority bytes."""
    h = hivex.Hivex(hive_path)
    root = h.root()
    driverdb = safe_child(h, root, "DriverDatabase")
    if not driverdb:
        return []
    deviceids = safe_child(h, driverdb, "DeviceIds")
    if not deviceids:
        return []

    entries = []

    def _walk(node, prefix=""):
        for name, child in walk_children(h, node):
            path = f"{prefix}\\{name}" if prefix else name
            try:
                for val in h.node_values(child):
                    val_name = h.value_key(val)
                    if val_name.lower() == oem_inf.lower():
                        vtype, _ = h.value_type(val)
                        raw = h.value_value(val)
                        raw_bytes = raw[1] if isinstance(raw, tuple) else raw
                        priority = raw_bytes.hex() if isinstance(raw_bytes, bytes) else ""
                        entries.append({
                            "device_id": path,
                            "priority": priority,
                            "is_class_guid": path.startswith('{'),
                        })
            except Exception:
                pass
            _walk(child, path)

    _walk(deviceids)
    return entries


def _format_value(vtype, val):
    """Format a registry value for display."""
    if val is None:
        return "(none)"
    if vtype == 4:  # DWORD
        return f"0x{val:08x} ({val})"
    if vtype == 3 and isinstance(val, bytes):  # BINARY
        if len(val) <= 32:
            return val.hex(' ')
        return val[:32].hex(' ') + f" ... ({len(val)} bytes total)"
    if vtype == 7 and isinstance(val, list):  # MULTI_SZ
        return val
    return str(val)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_driver_details(info):
    """Print full driver details in human-readable form."""
    d = info

    boot_tag = " [BOOT-CRITICAL]" if d.get("boot_critical") else ""
    print(f"\n{'═' * 70}")
    print(f"  Driver: {d['search_term']}{boot_tag}")
    print(f"{'═' * 70}")

    # Basic identity
    print(f"\n  OEM INF:        {d['oem_inf']}")
    if d.get("package"):
        print(f"  DriverStore:    {d['package']}")

    # INF metadata
    meta = d.get("inf_metadata")
    if meta:
        print(f"\n  ── INF Metadata ──")
        if meta.get('class'):
            print(f"  Class:          {meta['class']} {meta.get('class_guid', '')}")
        if meta.get('manufacturer'):
            print(f"  Manufacturer:   {meta['manufacturer']}")
        if meta.get('provider') and meta['provider'] != meta.get('manufacturer'):
            print(f"  Provider:       {meta['provider']}")
        if meta.get('driver_date'):
            print(f"  Driver date:    {meta['driver_date']}")
        if meta.get('driver_version'):
            print(f"  Driver version: {meta['driver_version']}")
        if meta.get('catalog_file'):
            print(f"  Catalog file:   {meta['catalog_file']}")
        if meta.get('pnp_lockdown'):
            print(f"  PnP lockdown:   {meta['pnp_lockdown']}")

    # Service details
    svc = d.get("service_details")
    if svc:
        print(f"\n  ── Service Registry (ControlSet001\\Services\\{d['service_name']}) ──")
        for name, entry in sorted(svc["values"].items()):
            val = entry["value"]
            if isinstance(val, list):
                val = ", ".join(val)
            print(f"  {name:<22} {entry['type']:<16} {val}")

        for subkey_name, subkey_data in sorted(svc["subkeys"].items()):
            print(f"\n  ── {subkey_name} ──")
            for name, entry in sorted(subkey_data["values"].items()):
                val = entry["value"]
                if isinstance(val, list):
                    val = ", ".join(val)
                print(f"    {name:<20} {entry['type']:<16} {val}")

            for sub2_name, sub2_data in sorted(subkey_data.get("subkeys", {}).items()):
                print(f"\n  ── {subkey_name}\\{sub2_name} ──")
                for name, entry in sorted(sub2_data["values"].items()):
                    val = entry["value"]
                    if isinstance(val, list):
                        val = ", ".join(val)
                    print(f"    {name:<20} {entry['type']:<16} {val}")

    elif d.get("service_name"):
        print(f"\n  Service:        {d['service_name']} (no registry entry — PnP-only)")

    # Hardware IDs with priority
    devid_entries = d.get("device_id_entries", [])
    hw_entries = [e for e in devid_entries if not e["is_class_guid"]]
    class_entries = [e for e in devid_entries if e["is_class_guid"]]

    if hw_entries:
        print(f"\n  ── Hardware IDs (DriverDatabase\\DeviceIds) ──")
        for e in hw_entries:
            prio = e["priority"]
            prio_label = ""
            if prio.startswith("01"):
                prio_label = " (exact match)"
            elif prio.startswith("02"):
                prio_label = " (compatible)"
            print(f"  {e['device_id']:<58} [{prio}]{prio_label}")

    if class_entries:
        print(f"\n  ── Class GUID Entries ──")
        for e in class_entries:
            print(f"  {e['device_id']}")

    # DriverStore files
    files = d.get("driverstore_files", [])
    if files:
        print(f"\n  ── DriverStore Files (FileRepository\\{d['package']}) ──")
        for f in files:
            size = f.get("size")
            if size is not None:
                if size >= 1024 * 1024:
                    size_str = f"{size / (1024*1024):.1f} MB"
                elif size >= 1024:
                    size_str = f"{size / 1024:.1f} KB"
                else:
                    size_str = f"{size} B"
                print(f"  {f['name']:<40} {size_str:>10}")
            else:
                print(f"  {f['name']}")

    # System32\drivers copy
    sys32 = d.get("system32_driver")
    if sys32 is not None:
        if sys32:
            size_str = f"{sys32 / 1024:.1f} KB" if sys32 >= 1024 else f"{sys32} B"
            print(f"\n  ── Boot Driver (System32\\drivers) ──")
            print(f"  {d['service_name']}.sys{' ' * (37 - len(d['service_name']))} {size_str:>10}")
        else:
            print(f"\n  System32\\drivers\\{d['service_name']}.sys: NOT PRESENT")

    # CatRoot entry
    if d.get("catroot_present"):
        oem_cat = d['oem_inf'].replace('.inf', '.cat')
        print(f"\n  ── CatRoot ──")
        print(f"  {{F750E6C3-38EE-11D1-85E5-00C04FC295EE}}\\{oem_cat}: present")

    # PnpLockdownFiles
    lockdown = d.get("pnplockdown")
    if lockdown:
        print(f"\n  ── PnpLockdownFiles ──")
        for name, entry in sorted(lockdown.items()):
            val = entry["value"]
            if isinstance(val, list):
                val = ", ".join(val)
            print(f"  {name:<22} {entry['type']:<16} {val}")

    # DriverPackages metadata
    pkg = d.get("driverpackage_details")
    if pkg:
        print(f"\n  ── DriverPackages Registry (DriverDatabase\\DriverPackages\\{d['package']}) ──")
        for name, entry in sorted(pkg["values"].items()):
            val = entry["value"]
            if isinstance(val, list):
                val = ", ".join(val)
            print(f"  {name:<22} {entry['type']:<16} {val}")

        for subkey_name, subkey_data in sorted(pkg.get("subkeys", {}).items()):
            _print_subtree(subkey_name, subkey_data, indent=2)

    print()


def _print_subtree(name, data, indent=2):
    """Recursively print a registry subtree."""
    prefix = " " * indent
    print(f"\n{prefix}── {name} ──")
    for vname, entry in sorted(data.get("values", {}).items()):
        val = entry["value"]
        if isinstance(val, list):
            val = ", ".join(val)
        print(f"{prefix}  {vname:<20} {entry['type']:<16} {val}")
    for sub_name, sub_data in sorted(data.get("subkeys", {}).items()):
        _print_subtree(f"{name}\\{sub_name}", sub_data, indent)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Show full details of a driver installed in an offline Windows image",
    )
    parser.add_argument(
        '--image', required=True,
        help='Path to Windows disk image (VHDX/qcow2)',
    )
    parser.add_argument(
        '--name', required=True,
        help='Driver to look up: service name (viostor), OEM INF (oem4.inf), '
             'or package prefix (viostor.inf_amd64_...)',
    )
    parser.add_argument(
        '--json', action='store_true',
        help='Output as JSON',
    )
    args = parser.parse_args()

    print(f"Scanning image: {args.image}")

    # 1. Find Windows partition
    print("  Finding Windows partition...")
    partition = find_windows_partition(args.image)
    print(f"  Windows found on {partition}")

    with tempfile.TemporaryDirectory() as tmpdir:
        # 2. Download hives
        system_hive = os.path.join(tmpdir, "SYSTEM")
        software_hive = os.path.join(tmpdir, "SOFTWARE")
        drivers_hive = os.path.join(tmpdir, "DRIVERS")

        print("  Downloading registry hives...")
        download_file(args.image, partition, "/Windows/System32/config/SYSTEM", system_hive)
        download_file(args.image, partition, "/Windows/System32/config/SOFTWARE", software_hive)
        has_drivers_hive = download_file_optional(
            args.image, partition, "/Windows/System32/config/DRIVERS", drivers_hive,
        )

        # 3. Build index and find the driver
        print(f"  Searching for '{args.name}'...")
        index = build_oem_index(system_hive, drivers_hive if has_drivers_hive else None)

        oem_inf = find_driver(index, args.name)
        if oem_inf is None:
            if not any(True for _ in []):  # find_driver already printed ambiguity message
                print(f"  Driver '{args.name}' not found.")
                print(f"  Available drivers:")
                for oem in sorted(index, key=lambda n: int(re.search(r'\d+', n).group())):
                    e = index[oem]
                    pkg = e.get("package", "")
                    svc = e["service"]["name"] if e["service"] else "—"
                    print(f"    {oem:<14} package={pkg:<45} service={svc}")
            sys.exit(1)

        entry = index[oem_inf]
        package_dir = entry["package"]
        service_name = entry["service"]["name"] if entry["service"] else None

        print(f"  Found: {oem_inf} -> {package_dir}")

        # 4. Gather deep details
        info = {
            "search_term": args.name,
            "oem_inf": oem_inf,
            "package": package_dir,
            "service_name": service_name,
            "configurations": entry["configurations"],
            "hardware_ids": entry["hardware_ids"],
            "boot_critical": (
                entry["service"] is not None and entry["service"].get("start") == 0
            ),
        }

        # INF metadata — download and parse
        print("  Downloading INF file...")
        inf_local = os.path.join(tmpdir, oem_inf)
        if download_file_optional(args.image, partition, f"/Windows/INF/{oem_inf}", inf_local):
            info["inf_metadata"] = parse_inf_full(inf_local)
        else:
            info["inf_metadata"] = None

        # Service registry
        if service_name:
            print(f"  Reading service registry (Services\\{service_name})...")
            info["service_details"] = get_service_details(system_hive, service_name)

        # Device ID entries with priority
        print("  Reading DeviceIds entries...")
        info["device_id_entries"] = get_device_id_entries(system_hive, oem_inf)
        if has_drivers_hive:
            info["device_id_entries"] += get_device_id_entries(drivers_hive, oem_inf)

        # DriverStore file listing
        if package_dir:
            print("  Listing DriverStore files...")
            store_dir = f"/Windows/System32/DriverStore/FileRepository/{package_dir}"
            filenames = list_directory(args.image, partition, store_dir)
            file_entries = []
            for fname in filenames:
                size = stat_file(args.image, partition, f"{store_dir}/{fname}")
                file_entries.append({"name": fname, "size": size})
            info["driverstore_files"] = file_entries

        # System32\drivers copy (boot-critical check)
        if service_name:
            sys32_path = f"/Windows/System32/drivers/{service_name}.sys"
            sys32_size = stat_file(args.image, partition, sys32_path)
            info["system32_driver"] = sys32_size

        # CatRoot entry
        oem_cat = oem_inf.replace('.inf', '.cat')
        catroot_path = f"/Windows/System32/CatRoot/{{F750E6C3-38EE-11D1-85E5-00C04FC295EE}}/{oem_cat}"
        info["catroot_present"] = stat_file(args.image, partition, catroot_path) is not None

        # PnpLockdownFiles
        if service_name:
            print("  Checking PnpLockdownFiles...")
            info["pnplockdown"] = get_pnplockdown_entry(software_hive, service_name)

        # DriverPackages metadata
        if package_dir:
            print("  Reading DriverPackages metadata...")
            # Check both hives
            info["driverpackage_details"] = get_driverpackage_details(system_hive, package_dir)
            if info["driverpackage_details"] is None and has_drivers_hive:
                info["driverpackage_details"] = get_driverpackage_details(drivers_hive, package_dir)

        # 5. Output
        if args.json:
            # Make JSON-serializable: bytes -> hex strings
            def _sanitize(obj):
                if isinstance(obj, bytes):
                    return obj.hex(' ')
                if isinstance(obj, dict):
                    return {k: _sanitize(v) for k, v in obj.items()}
                if isinstance(obj, list):
                    return [_sanitize(v) for v in obj]
                if isinstance(obj, set):
                    return sorted(_sanitize(v) for v in obj)
                return obj
            print(json.dumps(_sanitize(info), indent=2))
        else:
            print_driver_details(info)


if __name__ == '__main__':
    main()
