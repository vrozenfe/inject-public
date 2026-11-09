#!/usr/bin/env python3
"""
Enumerate 3rd-party (OEM) drivers installed in an offline Windows image.

Walks the registry (DriverDatabase, Services) and the Windows\\INF directory
to build a complete picture of every non-inbox driver: which DriverStore
package it maps to, what hardware IDs it handles, whether it has a
boot-critical service, and (with --parse-infs) the full class/provider/
version metadata from the INF file itself.

Designed as a companion to inject_driver.py — useful for:
  - Pre-migration inventory (what drivers does this Windows VM have?)
  - Post-injection verification (did our injected drivers land correctly?)
  - Debugging (which oem*.inf owns a specific PCI device?)

Usage:
    python3 list_drivers.py --image /path/to/disk.qcow2
    python3 list_drivers.py --image /path/to/disk.vhdx --parse-infs
    python3 list_drivers.py --image /path/to/disk.qcow2 --json
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

try:
    import hivex
except ImportError:
    print("ERROR: python3-hivex not installed")
    print("Install with: sudo dnf install python3-hivex")
    sys.exit(1)


# ---------------------------------------------------------------------------
# guestfish helpers (same patterns as detect_target_os.py / inject_driver.py)
# ---------------------------------------------------------------------------

def guestfish_ro(image_path, commands):
    """Run guestfish commands read-only against the image."""
    cmd = f"run\n{commands}\n"
    result = subprocess.run(
        ['guestfish', '--ro', '-a', str(image_path)],
        input=cmd, text=True, capture_output=True,
    )
    return result


def find_windows_partition(image_path):
    """Probe each partition for Windows\\System32\\config\\SOFTWARE."""
    result = guestfish_ro(image_path, "list-filesystems")
    if result.returncode != 0:
        raise RuntimeError(f"list-filesystems failed: {result.stderr}")

    partitions = [
        line.split(':')[0].strip()
        for line in result.stdout.splitlines()
        if line.strip()
    ]
    for part in partitions:
        check = guestfish_ro(
            image_path,
            f"mount-ro {part} /\n"
            f"is-file /Windows/System32/config/SOFTWARE\n",
        )
        if check.returncode == 0 and check.stdout.strip().splitlines()[-1] == 'true':
            return part
    raise RuntimeError(f"No Windows partition found among: {partitions}")


def download_file(image_path, partition, remote_path, local_path):
    """Download a single file from the image (read-only mount)."""
    result = guestfish_ro(
        image_path,
        f"mount-ro {partition} /\n"
        f"download {remote_path} {local_path}\n",
    )
    if result.returncode != 0:
        raise RuntimeError(f"Failed to download {remote_path}: {result.stderr}")


def list_oem_infs(image_path, partition):
    """Return sorted list of oem*.inf filenames in Windows\\INF."""
    result = guestfish_ro(
        image_path,
        f"mount-ro {partition} /\nls /Windows/INF\n",
    )
    if result.returncode != 0:
        raise RuntimeError(f"Failed to list Windows\\INF: {result.stderr}")

    oem_infs = []
    for line in result.stdout.splitlines():
        name = line.strip()
        if re.match(r'oem\d+\.inf$', name, re.IGNORECASE):
            oem_infs.append(name.lower())
    return sorted(oem_infs, key=lambda n: int(re.search(r'\d+', n).group()))


def download_oem_infs(image_path, partition, oem_infs, dest_dir):
    """Download a batch of oem*.inf files from Windows\\INF in one guestfish session."""
    if not oem_infs:
        return
    commands = f"mount-ro {partition} /\n"
    for inf in oem_infs:
        local = os.path.join(dest_dir, inf)
        commands += f"download /Windows/INF/{inf} {local}\n"
    result = guestfish_ro(image_path, commands)
    if result.returncode != 0:
        # Non-fatal — some INFs may have been removed from disk but left
        # in the registry; we'll still report them, just without parsed
        # metadata.
        print(f"  Warning: some INF downloads failed: {result.stderr.strip()}", file=sys.stderr)


# ---------------------------------------------------------------------------
# hivex helpers
# ---------------------------------------------------------------------------

def read_value(h, node, name, default=None):
    """Read a single registry value; returns default on missing."""
    try:
        val = h.node_get_value(node, name)
    except Exception:
        return default
    vtype, _vlen = h.value_type(val)
    if vtype in (1, 2):       # REG_SZ, REG_EXPAND_SZ
        return h.value_string(val)
    if vtype == 4:            # REG_DWORD
        return h.value_dword(val)
    if vtype == 7:            # REG_MULTI_SZ
        return h.value_multiple_strings(val)
    return default


def safe_child(h, node, name):
    """Get a child node, returning None on failure."""
    try:
        return h.node_get_child(node, name)
    except Exception:
        return None


def walk_children(h, node):
    """Yield (name, child_node) for each child of node."""
    try:
        children = h.node_children(node)
    except Exception:
        return
    for child in children:
        try:
            yield h.node_name(child), child
        except Exception:
            continue


# ---------------------------------------------------------------------------
# Registry enumeration
# ---------------------------------------------------------------------------

def enum_driver_inf_files(h, driverdb_node):
    """
    Walk DriverDatabase\\DriverInfFiles — one subkey per published oemN.inf.

    Returns dict: {
        "oem0.inf": {
            "package": "viostor.inf_x86_abc123...",  # Active package dir
            "configurations": ["viostor_Inst", ...],
        },
        ...
    }
    """
    result = {}
    inffiles_node = safe_child(h, driverdb_node, "DriverInfFiles")
    if inffiles_node is None:
        return result

    for name, child in walk_children(h, inffiles_node):
        if not re.match(r'oem\d+\.inf$', name, re.IGNORECASE):
            continue
        name_lower = name.lower()
        package = read_value(h, child, "Active")
        if package is None:
            # Fall back to default value (REG_MULTI_SZ)
            packages = read_value(h, child, "")
            package = packages[0] if isinstance(packages, list) and packages else None
        configurations = read_value(h, child, "Configurations") or []
        result[name_lower] = {
            "package": package,
            "configurations": configurations if isinstance(configurations, list) else [],
        }
    return result


def enum_device_ids(h, driverdb_node):
    """
    Walk DriverDatabase\\DeviceIds to build a reverse map:
      oem_inf -> [list of hardware IDs it handles]

    The tree looks like:
      DeviceIds\\PCI\\VEN_1AF4&DEV_1001  -> values: "oem4.inf" = ...
      DeviceIds\\PCI\\VEN_1AF4&DEV_1001&SUBSYS_00021AF4&REV_00 -> ...
      DeviceIds\\{ClassGUID} -> "oemN.inf" = ...  (class catalog entry)
    """
    oem_hwids = {}  # oem_inf -> set of hardware ID strings
    deviceids_node = safe_child(h, driverdb_node, "DeviceIds")
    if deviceids_node is None:
        return oem_hwids

    def _walk_deviceids(node, prefix=""):
        """Recurse through DeviceIds subtree."""
        for name, child in walk_children(h, node):
            path = f"{prefix}\\{name}" if prefix else name
            # Check if this node has any oemN.inf values
            try:
                values = h.node_values(child)
            except Exception:
                values = []
            for val in values:
                try:
                    val_name = h.value_key(val)
                except Exception:
                    continue
                if re.match(r'oem\d+\.inf$', val_name, re.IGNORECASE):
                    oem_key = val_name.lower()
                    if oem_key not in oem_hwids:
                        oem_hwids[oem_key] = set()
                    # Only add non-GUID paths as hardware IDs
                    # (GUIDs like {4d36e97d-...} are class catalog entries, not hw IDs)
                    if not path.startswith('{'):
                        oem_hwids[oem_key].add(path)
            # Recurse into children
            _walk_deviceids(child, path)

    _walk_deviceids(deviceids_node)
    return oem_hwids


def enum_services(h, root):
    """
    Walk ControlSet001\\Services for entries whose 'Owners' value references
    an oemN.inf, returning:
      oem_inf -> {
          "service_name": str,
          "start": int,      # 0=boot, 1=system, 2=auto, 3=demand, 4=disabled
          "type": int,
          "group": str,
          "image_path": str,
          "display_name": str,
      }
    """
    START_TYPES = {0: "Boot", 1: "System", 2: "Auto", 3: "Demand", 4: "Disabled"}
    result = {}
    cs001 = safe_child(h, root, "ControlSet001")
    if cs001 is None:
        return result
    services_node = safe_child(h, cs001, "Services")
    if services_node is None:
        return result

    for svc_name, svc_node in walk_children(h, services_node):
        owners = read_value(h, svc_node, "Owners")
        if owners is None:
            continue
        # Owners is REG_MULTI_SZ — list of owning INFs
        if isinstance(owners, str):
            owners = [owners]
        for owner in owners:
            if re.match(r'oem\d+\.inf$', owner, re.IGNORECASE):
                start_val = read_value(h, svc_node, "Start")
                result[owner.lower()] = {
                    "service_name": svc_name,
                    "start": start_val,
                    "start_type": START_TYPES.get(start_val, f"Unknown({start_val})"),
                    "type": read_value(h, svc_node, "Type"),
                    "group": read_value(h, svc_node, "Group", ""),
                    "image_path": read_value(h, svc_node, "ImagePath", ""),
                    "display_name": read_value(h, svc_node, "DisplayName", ""),
                }
    return result


def enum_hive(hive_path, label="SYSTEM"):
    """
    Enumerate DriverDatabase + Services from a single hive file.
    Returns (driver_inf_files, device_ids, services).
    """
    h = hivex.Hivex(hive_path)
    root = h.root()

    driverdb = safe_child(h, root, "DriverDatabase")
    if driverdb is not None:
        inf_files = enum_driver_inf_files(h, driverdb)
        device_ids = enum_device_ids(h, driverdb)
    else:
        inf_files = {}
        device_ids = {}

    services = enum_services(h, root)
    return inf_files, device_ids, services


# ---------------------------------------------------------------------------
# INF parser (lightweight — just the fields we need for the listing)
# ---------------------------------------------------------------------------

def parse_inf_metadata(inf_path):
    """
    Quick parse of an INF file to extract [Version] and [Manufacturer] metadata.
    Returns dict with class, class_guid, provider, manufacturer, driver_ver,
    catalog_file.
    """
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

    # Parse [Strings] first for token resolution
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

    # Parse [Version] and [Manufacturer] sections in one pass
    current_section = None
    result = {
        'class': '', 'class_guid': '', 'provider': '', 'manufacturer': '',
        'driver_ver': '', 'catalog_file': '',
    }
    for line in content.split('\n'):
        line = line.rstrip('\r').strip()
        if line.startswith('['):
            current_section = line.lower().strip('[]').strip()
            continue

        if current_section == 'version' and '=' in line:
            # Strip inline comments
            comment_pos = -1
            in_q = False
            for i, ch in enumerate(line):
                if ch == '"':
                    in_q = not in_q
                elif ch == ';' and not in_q:
                    comment_pos = i
                    break
            if comment_pos >= 0:
                line = line[:comment_pos].strip()
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
            elif key == 'catalogfile':
                result['catalog_file'] = val

        elif current_section == 'manufacturer' and '=' in line:
            # [Manufacturer] keys are "%ManufacturerName% = ..."
            # The key (left of '=') is the manufacturer token.
            key, _, _ = line.partition('=')
            mfr = resolve(key.strip().strip('"'))
            if mfr and not result['manufacturer']:
                result['manufacturer'] = mfr

    return result


# ---------------------------------------------------------------------------
# Merge and report
# ---------------------------------------------------------------------------

def build_driver_list(oem_infs_on_disk, system_data, drivers_data, inf_metadata):
    """
    Merge all data sources into a unified list of driver records, one per
    oemN.inf.
    """
    sys_inf_files, sys_device_ids, sys_services = system_data
    drv_inf_files, drv_device_ids, drv_services = drivers_data

    # Merge the two hive sources
    all_inf_files = {**sys_inf_files, **drv_inf_files}
    all_device_ids = {}
    for src in [sys_device_ids, drv_device_ids]:
        for oem, hwids in src.items():
            all_device_ids.setdefault(oem, set()).update(hwids)
    all_services = {**sys_services, **drv_services}

    # The authoritative list is the union of: on-disk oem*.inf files AND
    # anything referenced in DriverInfFiles (a driver might have its INF
    # deleted but still be registered, or vice versa).
    all_oems = sorted(
        set(oem_infs_on_disk) | set(all_inf_files.keys()),
        key=lambda n: int(re.search(r'\d+', n).group()),
    )

    drivers = []
    for oem in all_oems:
        rec = {"oem_inf": oem}

        # DriverInfFiles data
        inf_entry = all_inf_files.get(oem, {})
        rec["package"] = inf_entry.get("package", "")
        rec["configurations"] = inf_entry.get("configurations", [])

        # Hardware IDs
        rec["hardware_ids"] = sorted(all_device_ids.get(oem, []))

        # Service
        svc = all_services.get(oem)
        if svc:
            rec["service"] = svc
        else:
            rec["service"] = None

        # INF metadata (from parsed file)
        meta = inf_metadata.get(oem)
        if meta:
            rec["class"] = meta.get("class", "")
            rec["class_guid"] = meta.get("class_guid", "")
            rec["provider"] = meta.get("provider", "")
            rec["manufacturer"] = meta.get("manufacturer", "")
            rec["driver_ver"] = meta.get("driver_ver", "")
            rec["catalog_file"] = meta.get("catalog_file", "")
        else:
            rec["class"] = ""
            rec["class_guid"] = ""
            rec["provider"] = ""
            rec["manufacturer"] = ""
            rec["driver_ver"] = ""
            rec["catalog_file"] = ""

        # On-disk status
        rec["on_disk"] = oem in oem_infs_on_disk
        rec["in_registry"] = oem in all_inf_files

        # Boot-critical flag
        rec["boot_critical"] = (
            svc is not None and svc.get("start") == 0
        )

        drivers.append(rec)

    return drivers


def print_summary(drivers):
    """Print a human-readable summary table."""
    if not drivers:
        print("No 3rd-party (OEM) drivers found.")
        return

    print(f"\nFound {len(drivers)} 3rd-party driver(s):\n")

    # Column widths
    col_oem = 12
    col_class = 16
    col_mfr = 22
    col_service = 16
    col_start = 8
    col_hwids = 0  # variable

    header = (
        f"{'OEM INF':<{col_oem}} "
        f"{'Class':<{col_class}} "
        f"{'Manufacturer':<{col_mfr}} "
        f"{'Service':<{col_service}} "
        f"{'Start':<{col_start}} "
        f"Hardware IDs"
    )
    print(header)
    print("─" * len(header) + "─" * 30)

    for d in drivers:
        svc_name = d["service"]["service_name"] if d["service"] else "—"
        start_type = d["service"]["start_type"] if d["service"] else "—"
        mfr = d["manufacturer"] or d["provider"] or "—"
        hwids = ", ".join(d["hardware_ids"][:3])
        if len(d["hardware_ids"]) > 3:
            hwids += f" (+{len(d['hardware_ids']) - 3} more)"

        flags = ""
        if d["boot_critical"]:
            flags = " [BOOT]"
        if not d["on_disk"]:
            flags += " [NO FILE]"
        if not d["in_registry"]:
            flags += " [NO REG]"

        line = (
            f"{d['oem_inf']:<{col_oem}} "
            f"{d['class']:<{col_class}} "
            f"{mfr:<{col_mfr}} "
            f"{svc_name:<{col_service}} "
            f"{start_type:<{col_start}} "
            f"{hwids}"
            f"{flags}"
        )
        print(line)

    # Summary stats
    boot_count = sum(1 for d in drivers if d["boot_critical"])
    no_file = sum(1 for d in drivers if not d["on_disk"])
    no_reg = sum(1 for d in drivers if not d["in_registry"])
    print()
    if boot_count:
        print(f"  Boot-critical drivers: {boot_count}")
    if no_file:
        print(f"  Registry-only (INF missing from disk): {no_file}")
    if no_reg:
        print(f"  Disk-only (not in DriverDatabase): {no_reg}")


def print_verbose(drivers):
    """Print detailed per-driver information."""
    if not drivers:
        print("No 3rd-party (OEM) drivers found.")
        return

    print(f"\nFound {len(drivers)} 3rd-party driver(s):\n")

    for i, d in enumerate(drivers):
        if i > 0:
            print()
        boot_tag = " [BOOT-CRITICAL]" if d["boot_critical"] else ""
        print(f"── {d['oem_inf']}{boot_tag} ──")
        if d["class"]:
            print(f"  Class:          {d['class']} {d['class_guid']}")
        if d["manufacturer"]:
            print(f"  Manufacturer:   {d['manufacturer']}")
        if d["provider"] and d["provider"] != d["manufacturer"]:
            print(f"  Provider:       {d['provider']}")
        if d["driver_ver"]:
            print(f"  Driver version: {d['driver_ver']}")
        if d["package"]:
            print(f"  DriverStore:    {d['package']}")
        if d["catalog_file"]:
            print(f"  Catalog:        {d['catalog_file']}")
        if d["configurations"]:
            print(f"  Configurations: {', '.join(d['configurations'])}")

        if d["service"]:
            svc = d["service"]
            print(f"  Service:        {svc['service_name']} "
                  f"(Start={svc['start_type']}, Group={svc['group'] or '—'})")
            if svc["image_path"]:
                print(f"  ImagePath:      {svc['image_path']}")

        if d["hardware_ids"]:
            print(f"  Hardware IDs:   ({len(d['hardware_ids'])})")
            for hwid in d["hardware_ids"]:
                print(f"    {hwid}")

        status = []
        if d["on_disk"]:
            status.append("INF on disk")
        else:
            status.append("INF MISSING from disk")
        if d["in_registry"]:
            status.append("in DriverDatabase")
        else:
            status.append("NOT in DriverDatabase")
        print(f"  Status:         {', '.join(status)}")


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

_MS_PATTERNS = re.compile(
    r'\bmicrosoft\b', re.IGNORECASE,
)


def _is_microsoft(driver_rec):
    """True if the driver's manufacturer or provider looks like Microsoft."""
    for field in ('manufacturer', 'provider'):
        if _MS_PATTERNS.search(driver_rec.get(field, '')):
            return True
    return False


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="List 3rd-party (OEM) drivers installed in an offline Windows image",
    )
    parser.add_argument(
        '--image', required=True,
        help='Path to Windows disk image (VHDX/qcow2)',
    )
    parser.add_argument(
        '--parse-infs', action='store_true',
        help='Download and parse each oem*.inf for full metadata '
             '(class, provider, version). Slower but more informative.',
    )
    parser.add_argument(
        '--verbose', '-v', action='store_true',
        help='Print detailed per-driver information instead of summary table',
    )
    parser.add_argument(
        '--no-microsoft', action='store_true',
        help='Hide Microsoft drivers — show only true 3rd-party drivers '
             '(implies --parse-infs, since manufacturer comes from the INF)',
    )
    parser.add_argument(
        '--json', action='store_true',
        help='Output as JSON (implies --parse-infs)',
    )
    args = parser.parse_args()

    if args.json or args.no_microsoft:
        args.parse_infs = True

    print(f"Scanning image: {args.image}")

    # 1. Find Windows partition
    print("  Finding Windows partition...")
    partition = find_windows_partition(args.image)
    print(f"  Windows found on {partition}")

    with tempfile.TemporaryDirectory() as tmpdir:
        # 2. List oem*.inf files on disk
        print("  Listing OEM INFs in Windows\\INF...")
        oem_infs_on_disk = list_oem_infs(args.image, partition)
        print(f"  Found {len(oem_infs_on_disk)} oem*.inf file(s) on disk")

        # 3. Download registry hives
        print("  Downloading SYSTEM hive...")
        system_hive = os.path.join(tmpdir, "SYSTEM")
        download_file(args.image, partition, "/Windows/System32/config/SYSTEM", system_hive)

        drivers_hive = os.path.join(tmpdir, "DRIVERS")
        drivers_data = ({}, {}, {})
        try:
            print("  Downloading DRIVERS hive...")
            download_file(args.image, partition, "/Windows/System32/config/DRIVERS", drivers_hive)
            has_drivers_hive = True
        except RuntimeError:
            print("  (No DRIVERS hive — pre-Win10 or not present)")
            has_drivers_hive = False

        # 4. Enumerate registry
        print("  Enumerating SYSTEM registry...")
        system_data = enum_hive(system_hive, "SYSTEM")

        if has_drivers_hive:
            print("  Enumerating DRIVERS registry...")
            drivers_data = enum_hive(drivers_hive, "DRIVERS")

        # 5. Optionally parse INF files
        inf_metadata = {}
        if args.parse_infs and oem_infs_on_disk:
            print(f"  Downloading and parsing {len(oem_infs_on_disk)} INF file(s)...")
            inf_dir = os.path.join(tmpdir, "infs")
            os.makedirs(inf_dir)
            download_oem_infs(args.image, partition, oem_infs_on_disk, inf_dir)
            for inf_name in oem_infs_on_disk:
                inf_path = os.path.join(inf_dir, inf_name)
                if os.path.exists(inf_path):
                    meta = parse_inf_metadata(inf_path)
                    if meta:
                        inf_metadata[inf_name] = meta

        # 6. Build unified list
        drivers = build_driver_list(
            oem_infs_on_disk, system_data, drivers_data, inf_metadata,
        )

        # 7. Filter
        if args.no_microsoft:
            before = len(drivers)
            drivers = [
                d for d in drivers
                if not _is_microsoft(d)
            ]
            hidden = before - len(drivers)
            if hidden:
                print(f"  (filtered out {hidden} Microsoft driver(s))")

        # 8. Output
        if args.json:
            # Convert sets to lists for JSON serialization
            for d in drivers:
                if d["service"] and isinstance(d["service"].get("group"), type(None)):
                    d["service"]["group"] = ""
            print(json.dumps(drivers, indent=2))
        elif args.verbose or args.parse_infs:
            print_verbose(drivers)
        else:
            print_summary(drivers)


if __name__ == '__main__':
    main()
