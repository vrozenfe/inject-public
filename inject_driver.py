#!/usr/bin/env python3
"""
Universal Windows Driver Injection Script
==========================================

This script replicates Microsoft DISM's driver injection algorithm to inject
ANY Windows driver into an offline Windows image (VHDX, qcow2, etc.) using
Linux tools (guestfish + hivex).

Based on reverse-engineering DISM behavior from registry diffs.

Usage:
    python3 inject_driver.py --image base_disk.vhdx --driver /path/to/driver/w10/x86

Author: Reverse-engineered from DISM analysis
License: Educational/Operational use
"""

import sys
import os
import struct
import hashlib
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from configparser import ConfigParser

try:
    import hivex
except ImportError:
    print("ERROR: python3-hivex not installed")
    print("Install with: sudo dnf install python3-hivex")
    sys.exit(1)


class INFParser:
    """
    Custom parser for Windows .inf driver files.

    ConfigParser doesn't work well for INF files because:
    - INF files allow duplicate keys (multiple device entries)
    - Case sensitivity varies
    - Continuation lines with backslash
    - Comments with semicolons

    This parser handles all these cases correctly.
    """

    def __init__(self, inf_path):
        self.inf_path = Path(inf_path)
        self.inf_name = self.inf_path.stem
        self.data = {}
        self.sections = {}  # {section_name: {key: [values]}}

        # Read and parse INF file
        self._read_inf()
        self._parse()

        # Store inf_name in data for easy access
        self.data['inf_name'] = self.inf_name

    def _read_inf(self):
        """
        Read INF file and parse into sections.

        Handles:
        - Multiple encodings (UTF-16LE, UTF-8)
        - Line continuations (backslash at end)
        - Comments (semicolons)
        - Duplicate keys (stored as lists)
        - Case-insensitive sections
        """
        # Detect UTF-16LE via its BOM rather than probing with try/except:
        # decoding a plain-ASCII/UTF-8 file as UTF-16LE only raises an error
        # when its byte count is odd, so for even-length files the probe
        # silently "succeeds" with garbage instead of falling through to
        # UTF-8 (found via vioinput.inf, which has no BOM but happens to be
        # an even number of bytes).
        with open(self.inf_path, 'rb') as f:
            raw = f.read()

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
            raise ValueError(f"Could not decode INF file: {self.inf_path}")

        # Parse line by line
        current_section = None
        current_line = ""

        for line in content.split('\n'):
            line = line.rstrip('\r')

            # Handle line continuation (backslash at end)
            if line.endswith('\\'):
                current_line += line[:-1].strip() + " "
                continue
            else:
                line = current_line + line
                current_line = ""

            # Remove inline comments
            if ';' in line:
                # But preserve semicolons in quoted strings
                in_quotes = False
                comment_pos = -1
                for i, char in enumerate(line):
                    if char == '"':
                        in_quotes = not in_quotes
                    elif char == ';' and not in_quotes:
                        comment_pos = i
                        break
                if comment_pos >= 0:
                    line = line[:comment_pos]

            line = line.strip()
            if not line:
                continue

            # Section header: [SectionName]
            if line.startswith('[') and line.endswith(']'):
                current_section = line[1:-1].strip()
                if current_section not in self.sections:
                    self.sections[current_section] = {}
                continue

            # Key-value pair: Key = Value
            if '=' in line and current_section:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()

                # Store as list to handle duplicate keys
                if key not in self.sections[current_section]:
                    self.sections[current_section][key] = []
                self.sections[current_section][key].append(value)
            elif current_section:
                # Bare directive line with no '=' (e.g. AddReg's "HKR, ..." entries).
                # Kept in order under a synthetic key so section-specific parsers
                # (like _parse_addreg_section) can find them.
                self.sections[current_section].setdefault('__raw_lines__', []).append(line)

    def _get_section(self, section_name, case_insensitive=True):
        """Get section by name, optionally case-insensitive"""
        if section_name in self.sections:
            return self.sections[section_name]

        if case_insensitive:
            section_name_lower = section_name.lower()
            for sec_name, sec_data in self.sections.items():
                if sec_name.lower() == section_name_lower:
                    return sec_data

        return None

    def _find_key(self, section, key):
        """
        Look up a key within a section dict case-insensitively, matching
        real INF parsing semantics (both section names AND key names are
        case-insensitive - e.g. some drivers spell it "ClassGuid", others
        "ClassGUID"). Returns the actual stored key name, or None.
        """
        if key in section:
            return key
        key_lower = key.lower()
        for existing_key in section:
            if existing_key.lower() == key_lower:
                return existing_key
        return None

    def _get_value(self, section_name, key, default=None, index=0):
        """Get value from section, returns first match by default"""
        section = self._get_section(section_name)
        if not section:
            return default

        actual_key = self._find_key(section, key)
        if actual_key is not None and len(section[actual_key]) > index:
            return section[actual_key][index]

        return default

    def _get_all_values(self, section_name, key):
        """Get all values for a key (for duplicate keys)"""
        section = self._get_section(section_name)
        if not section:
            return []
        actual_key = self._find_key(section, key)
        if actual_key is None:
            return []
        return section[actual_key]

    def _parse(self):
        """Extract all relevant data from INF"""
        self._parse_strings()
        self._parse_version()
        self._parse_manufacturer()
        self._parse_source_files()
        self._parse_service()

    def _parse_version(self):
        """Parse [Version] section (case-insensitive)"""
        version_data = self._get_section('Version', case_insensitive=True)
        if not version_data:
            raise ValueError("Invalid INF: Missing [Version] section")

        self.data['class'] = self._get_value('Version', 'Class', 'Unknown')
        self.data['class_guid'] = self._get_value('Version', 'ClassGUID', '')
        self.data['provider'] = self._resolve_tokens(self._get_value('Version', 'Provider', 'Unknown'))
        self.data['driver_ver'] = self._get_value('Version', 'DriverVer', '')
        self.data['catalog_file'] = self._get_value('Version', 'CatalogFile', f'{self.inf_name}.cat')
        self.data['pnp_lockdown'] = self._get_value('Version', 'PnpLockdown', '0')

    def _parse_manufacturer(self):
        """
        Parse [Manufacturer] section to extract hardware IDs.

        Handles platform decorations like:
        - NTx86 (32-bit x86)
        - NTamd64 (64-bit x64)
        - NT{arch}.{version} (e.g., NTx86.10.0 for Win10 x86)

        Example:
            [Manufacturer]
            %VENDOR% = VioStor,NTx86.10.0

            [VioStor.NTx86.10.0]
            %DeviceDesc% = InstallSection, PCI\\VEN_1AF4&DEV_1001, PCI\\VEN_1AF4&DEV_1042
            %DeviceDesc% = InstallSection, PCI\\VEN_1AF4&DEV_1048, PCI\\VEN_1AF4&DEV_1049
        """
        self.data['hardware_ids'] = []
        # Richer per-hardware-ID records (hw_id/install_section/resolved vendor
        # and device description) needed to build DriverDatabase\DriverPackages
        # \...\Descriptors entries, which reference these resolved strings.
        self.data['hardware_id_entries'] = []

        manufacturer_data = self._get_section('Manufacturer', case_insensitive=True)
        if not manufacturer_data:
            return

        # Parse each manufacturer entry
        for key, values in manufacturer_data.items():
            if key == '__raw_lines__':
                continue
            # Ground truth shows DriverPackages\...\Descriptors stores the raw
            # lowercased "%token%" text (resolution happens separately via the
            # Strings subtree), so keep the bare token name, not its resolved value.
            vendor_token = key.strip().strip('%').lower()
            # Each value can be "BaseName,Decoration1,Decoration2,..."
            for value in values:
                parts = [p.strip() for p in value.split(',')]
                base_name = parts[0]
                decorations = parts[1:] if len(parts) > 1 else []

                # Try to find the most specific matching section
                # Priority: decorated sections first, then base section
                section_candidates = []

                # Add decorated sections (e.g., VioStor.NTx86.10.0)
                for decoration in decorations:
                    section_candidates.append(f"{base_name}.{decoration}")

                # Add base section as fallback
                section_candidates.append(base_name)

                # Find first existing section
                target_section = None
                for candidate in section_candidates:
                    if self._get_section(candidate):
                        target_section = candidate
                        break

                if not target_section:
                    continue

                # Extract hardware IDs from target section
                # IMPORTANT: Get ALL entries (duplicate keys supported now!)
                device_section = self._get_section(target_section)
                for device_key, device_values in device_section.items():
                    if device_key == '__raw_lines__':
                        continue
                    device_desc_token = device_key.strip().strip('%').lower()
                    # Each device entry: %DeviceDesc% = InstallSection, HWID1, HWID2, ...
                    for device_value in device_values:
                        parts = [x.strip() for x in device_value.split(',')]
                        install_section = parts[0] if parts else None
                        # Skip first part (install section), rest are hardware IDs
                        hw_ids = [x for x in parts[1:] if x and not x.startswith(';')]
                        self.data['hardware_ids'].extend(hw_ids)
                        for hw_id in hw_ids:
                            self.data['hardware_id_entries'].append({
                                'hw_id': hw_id,
                                'install_section': install_section,
                                'device_desc_token': device_desc_token,
                                'vendor_token': vendor_token,
                            })

    def _parse_source_files(self):
        """Parse [SourceDisksFiles] to get list of driver files"""
        self.data['source_files'] = []

        source_files_section = self._get_section('SourceDisksFiles', case_insensitive=True)
        if source_files_section:
            # Keys are filenames
            self.data['source_files'] = [k for k in source_files_section.keys() if k != '__raw_lines__']

    def _parse_service(self):
        """
        Parse service installation section.

        Also resolves the sibling sections DISM pulls registry data from when
        publishing a boot-critical driver:
          - the ServiceInstallSection's own AddReg (-> Services\\{name}\\Parameters)
          - the EventLogSection's AddReg (-> Services\\EventLog\\System\\{name})
          - the base install section's ".HW" AddReg (-> per-device interrupt
            policy, mirrored under DriverDatabase\\DriverPackages\\...\\Configurations)
        """
        self.data['service'] = None
        self.data['hw_addreg'] = []

        # Find .Services section
        for section_name in self.sections.keys():
            if section_name.endswith('.Services'):
                install_section = section_name[:-len('.Services')]
                service_line = self._get_value(section_name, 'AddService')
                if service_line:
                    # Format: ServiceName, Flags, ServiceInstallSection, EventLogSection
                    parts = [p.strip() for p in service_line.split(',')]
                    service_name = parts[0]
                    service_install_section = parts[2] if len(parts) > 2 else None
                    eventlog_install_section = parts[3] if len(parts) > 3 else None

                    if service_install_section and self._get_section(service_install_section):
                        params_addreg_name = self._get_value(service_install_section, 'AddReg')
                        params_addreg = self._parse_addreg_section(params_addreg_name) if params_addreg_name else []

                        eventlog_addreg = []
                        if eventlog_install_section and self._get_section(eventlog_install_section):
                            eventlog_addreg_name = self._get_value(eventlog_install_section, 'AddReg')
                            if eventlog_addreg_name:
                                eventlog_addreg = self._parse_addreg_section(eventlog_addreg_name)

                        self.data['service'] = {
                            'name': service_name,
                            'type': self._parse_constant(self._get_value(service_install_section, 'ServiceType', '1')),
                            'start': self._parse_constant(self._get_value(service_install_section, 'StartType', '3')),
                            'error_control': self._parse_constant(self._get_value(service_install_section, 'ErrorControl', '1')),
                            'binary': self._get_value(service_install_section, 'ServiceBinary', ''),
                            'group': self._get_value(service_install_section, 'LoadOrderGroup', ''),
                            'install_section': install_section,
                            'params_addreg': params_addreg,
                            'eventlog_addreg': eventlog_addreg,
                        }

                        hw_addreg_name = self._get_value(f"{install_section}.HW", 'AddReg')
                        if hw_addreg_name:
                            self.data['hw_addreg'] = self._parse_addreg_section(hw_addreg_name)
                    break

    def _parse_strings(self):
        """Parse [Strings] section into a lookup table used to resolve %token% references."""
        self.data['strings'] = {}
        section = self._get_section('Strings', case_insensitive=True)
        if not section:
            return
        for key, values in section.items():
            if key == '__raw_lines__' or not values:
                continue
            self.data['strings'][key.strip().lower()] = values[0].strip().strip('"')

    def _resolve_tokens(self, value):
        """
        Resolve %token% references against [Strings]. A doubled %% is an
        escaped literal percent (e.g. INF's "%%SystemRoot%%" -> "%SystemRoot%",
        where SystemRoot is an OS environment variable, not an INF token, and
        is deliberately left unresolved since it's not in [Strings]).
        """
        if value is None:
            return value
        value = value.replace('%%', '\x00PCT\x00')
        strings = self.data.get('strings', {})

        def repl(m):
            return strings.get(m.group(1).lower(), m.group(0))

        value = re.sub(r'%([^%]+)%', repl, value)
        return value.replace('\x00PCT\x00', '%')

    def _split_inf_fields(self, line):
        """Split a comma-separated INF directive line, respecting quoted strings."""
        fields = []
        current = ''
        in_quotes = False
        for ch in line:
            if ch == '"':
                in_quotes = not in_quotes
                continue
            if ch == ',' and not in_quotes:
                fields.append(current.strip())
                current = ''
            else:
                current += ch
        fields.append(current.strip())
        return fields

    def _resolve_flags(self, flags_str):
        """Resolve an AddReg flags field, which may be a literal int or a %TOKEN%."""
        flags_str = (flags_str or '').strip()
        if not flags_str:
            return 0
        if flags_str.startswith('%'):
            flags_str = self._resolve_tokens(flags_str)
        try:
            return int(flags_str, 0)
        except ValueError:
            return 0

    def _classify_addreg_type(self, flags):
        """
        Map an AddReg flags DWORD to a registry value type, per the standard
        FLG_ADDREG_* semantics used across our target INFs:
          0x10        -> FLG_ADDREG_KEYONLY (ensure key exists, no value)
          0x00010001  -> REG_DWORD   (high word 1, BINVALUETYPE bit set)
          0x00010000  -> REG_MULTI_SZ (high word 1, BINVALUETYPE bit clear)
          0x00020000  -> REG_EXPAND_SZ
          bit0 set, no high word -> REG_BINARY
          default     -> REG_SZ
        """
        if flags & 0x00000010:
            return 'keyonly'
        high = (flags >> 16) & 0xffff
        binvalue = flags & 0x00000001
        if high == 0x0001:
            return 'dword' if binvalue else 'multi_sz'
        if high == 0x0002:
            return 'expand_sz'
        if binvalue:
            return 'binary'
        return 'sz'

    def _parse_addreg_section(self, section_name):
        """
        Parse an AddReg section's "HKR, <subkey>, <valuename>, <flags>, <value>"
        directive lines into a list of {'subkey', 'name', 'type', 'value'} dicts,
        with %token% references already resolved against [Strings].
        """
        entries = []
        section = self._get_section(section_name, case_insensitive=True)
        if not section:
            return entries

        for line in section.get('__raw_lines__', []):
            fields = self._split_inf_fields(line)
            if not fields or fields[0].upper() != 'HKR':
                continue

            subkey = self._resolve_tokens(fields[1]) if len(fields) > 1 else ''
            valuename = self._resolve_tokens(fields[2]) if len(fields) > 2 else ''
            flags = self._resolve_flags(fields[3]) if len(fields) > 3 else 0
            raw_values = fields[4:] if len(fields) > 4 else []
            vtype = self._classify_addreg_type(flags)

            if vtype == 'keyonly':
                entries.append({'subkey': subkey, 'name': valuename, 'type': vtype, 'value': None})
                continue

            if vtype == 'multi_sz':
                value = [self._resolve_tokens(v) for v in raw_values]
            elif vtype == 'binary':
                value = [self._parse_constant(v) for v in raw_values]
            else:
                raw = self._resolve_tokens(raw_values[0]) if raw_values else ''
                value = self._parse_constant(raw) if vtype == 'dword' else raw

            entries.append({'subkey': subkey, 'name': valuename, 'type': vtype, 'value': value})

        return entries

    def _parse_constant(self, value):
        """Parse constant like %SERVICE_BOOT_START% or hex value"""
        # Common constants
        constants = {
            '%SERVICE_KERNEL_DRIVER%': 0x00000001,
            '%SERVICE_BOOT_START%': 0x00000000,
            '%SERVICE_SYSTEM_START%': 0x00000001,
            '%SERVICE_AUTO_START%': 0x00000002,
            '%SERVICE_DEMAND_START%': 0x00000003,
            '%SERVICE_ERROR_NORMAL%': 0x00000001,
        }

        value = value.strip()
        if value in constants:
            return constants[value]

        # Try to parse as hex or decimal
        try:
            if value.startswith('0x'):
                return int(value, 16)
            return int(value)
        except ValueError:
            return 0


def generate_driverstore_hash(inf_path):
    """
    Generate DriverStore hash.

    Microsoft's algorithm is proprietary, so we use MD5(inf_content)[0:16]
    for a deterministic, unique hash per driver version.
    """
    with open(inf_path, 'rb') as f:
        content = f.read()

    md5 = hashlib.md5(content).hexdigest()
    return md5[:16]  # Take first 16 hex chars


def encode_utf16le(s):
    """Encode string as UTF-16LE with null terminator for REG_SZ"""
    return (s + '\0').encode('utf-16le')


def encode_multi_sz(strings):
    """Encode list of strings as REG_MULTI_SZ"""
    result = '\0'.join(strings) + '\0\0'
    return result.encode('utf-16le')


def guid_to_binary(guid_str):
    """
    Encode a "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}" ClassGUID string as the
    16-byte little-endian binary GUID form Windows stores in the registry
    (Data1/Data2/Data3 little-endian, Data4 as-is).
    """
    s = guid_str.strip('{}')
    data1, data2, data3, data4a, data4b = s.split('-')
    return (
        struct.pack('<I', int(data1, 16)) +
        struct.pack('<H', int(data2, 16)) +
        struct.pack('<H', int(data3, 16)) +
        bytes.fromhex(data4a) +
        bytes.fromhex(data4b)
    )


def ensure_child_path(h, base_node, path):
    """Get-or-create a chain of child nodes under base_node for a backslash-separated path."""
    node = base_node
    for part in path.split('\\'):
        if not part:
            continue
        child = h.node_get_child(node, part)
        if child is None:
            child = h.node_add_child(node, part)
        node = child
    return node


def inject_addreg_values(h, base_node, addreg_entries):
    """
    Apply a list of parsed AddReg entries (see INFParser._parse_addreg_section)
    under base_node, creating any subkey chain each entry specifies.
    """
    for entry in addreg_entries:
        node = ensure_child_path(h, base_node, entry['subkey']) if entry['subkey'] else base_node

        vtype = entry['type']
        if vtype == 'keyonly':
            continue

        name = entry['name']
        value = entry['value']

        if vtype == 'dword':
            h.node_set_value(node, {"key": name, "t": 4, "value": struct.pack('<I', value & 0xffffffff)})
        elif vtype == 'sz':
            h.node_set_value(node, {"key": name, "t": 1, "value": encode_utf16le(value)})
        elif vtype == 'expand_sz':
            h.node_set_value(node, {"key": name, "t": 2, "value": encode_utf16le(value)})
        elif vtype == 'multi_sz':
            h.node_set_value(node, {"key": name, "t": 7, "value": encode_multi_sz(value)})
        elif vtype == 'binary':
            h.node_set_value(node, {"key": name, "t": 3, "value": bytes(b & 0xff for b in value)})


def _value_bytes(h, val_handle):
    """Normalize hivex's value_value() return (some bindings return (type, data))."""
    val_data = h.value_value(val_handle)
    return val_data[1] if isinstance(val_data, tuple) else val_data


def get_next_oem_number(image_path):
    """
    Find the next available oemN.inf number by scanning Windows\\INF for
    existing oem*.inf files and using the highest existing number + 1.

    This mirrors DISM's own documented and observed behavior. It deliberately
    does NOT trust DriverDatabase\\OemInfMap to pick the number: on a real
    Windows 10 image, oem0.inf/oem1.inf were already in use by inbox
    Microsoft printer drivers (prnms009.inf/prnms001.inf) that are not
    reflected in that bitmap at all. Scanning the bitmap for the lowest
    unset bit picked oem1.inf as "free" and silently overwrote the printer
    driver's published INF file - scanning the actual files on disk is the
    only way to avoid colliding with an already-published driver.
    """
    list_cmd = """
run
mount-options remove_hiberfile,force /dev/sda2 /
ls /Windows/INF
umount /
"""
    result = subprocess.run(
        ['guestfish', '--rw', '-a', str(image_path)],
        input=list_cmd,
        text=True,
        capture_output=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"Failed to list Windows\\INF: {result.stderr}")

    max_oem = 0
    for line in result.stdout.splitlines():
        m = re.match(r'oem(\d+)\.inf$', line.strip(), re.IGNORECASE)
        if m:
            max_oem = max(max_oem, int(m.group(1)))

    return max_oem + 1


def allocate_group_tag(h, grouporder_node, group_name):
    """
    Pick a Tag number for a service joining a load-order group: the smallest
    positive integer not already present in that group's existing
    GroupOrderList tag array. Real DISM assigned low, reused-looking tag
    numbers (0x21/0x22) rather than one past the historical max, which this
    mirrors - though the exact number isn't load-bearing for Windows, only
    uniqueness within the group is.

    Layout of ControlSet001\\Control\\GroupOrderList\\{group_name} (REG_BINARY):
    [count:u32][0x100][0x101][0x19][tag1:u32]...[tagN:u32]
    """
    try:
        val_handle = h.node_get_value(grouporder_node, group_name)
    except RuntimeError:
        val_handle = None

    used = set()
    if val_handle is not None:
        data = _value_bytes(h, val_handle)
        tag_bytes = data[16:]  # skip the 4 header dwords
        for i in range(0, len(tag_bytes) - 3, 4):
            used.add(struct.unpack('<I', tag_bytes[i:i + 4])[0])

    tag = 1
    while tag in used:
        tag += 1
    return tag


def update_group_order_list(h, grouporder_node, group_name, tag):
    """
    Append `tag` to ControlSet001\\Control\\GroupOrderList\\{group_name} and
    bump its leading count DWORD. Appending at the very end is correct
    regardless of the header layout, since it only needs the count field
    and the position just past the last existing tag.
    """
    try:
        val_handle = h.node_get_value(grouporder_node, group_name)
    except RuntimeError:
        val_handle = None

    if val_handle is None:
        new_data = struct.pack('<I', 1) + struct.pack('<I', tag)
    else:
        data = bytearray(_value_bytes(h, val_handle))
        count = struct.unpack('<I', data[0:4])[0]
        data[0:4] = struct.pack('<I', count + 1)
        data.extend(struct.pack('<I', tag))
        new_data = bytes(data)

    h.node_set_value(grouporder_node, {"key": group_name, "t": 3, "value": new_data})
    print(f"  ✓ Updated GroupOrderList\\{group_name}: added tag 0x{tag:02x}")


def update_oeminfmap_bit(h, driverdb_node, oem_number):
    """Set bit `oem_number` in DriverDatabase\\OemInfMap, creating it if absent."""
    try:
        val_handle = h.node_get_value(driverdb_node, "OemInfMap")
        oem_map = int.from_bytes(_value_bytes(h, val_handle), byteorder='little')
    except RuntimeError:
        oem_map = 0

    oem_map |= (1 << oem_number)
    num_bytes = max(1, (oem_map.bit_length() + 7) // 8)
    h.node_set_value(driverdb_node, {
        "key": "OemInfMap",
        "t": 3,  # REG_BINARY
        "value": oem_map.to_bytes(num_bytes, byteorder='little')
    })


def inject_class_catalog_entry(h, deviceids_node, class_guid, oem_inf):
    """
    Append this driver's oemN.inf to the per-class catalog list under
    DriverDatabase\\DeviceIds\\{ClassGUID}, using the REG_NONE empty-value
    presence marker DISM uses there.
    """
    class_node = h.node_get_child(deviceids_node, class_guid)
    if class_node is None:
        class_node = h.node_add_child(deviceids_node, class_guid)

    h.node_set_value(class_node, {"key": oem_inf, "t": 0, "value": b""})  # REG_NONE


def inject_driverinffiles_entry(h, driverinffiles_node, oem_inf, package_dir, install_sections):
    """
    DriverDatabase\\DriverInfFiles\\oem{N}.inf: maps the published INF to its
    DriverStore package (default value), marks it Active, and lists which
    install sections ("Configurations") were used.
    """
    oem_node = h.node_get_child(driverinffiles_node, oem_inf)
    if oem_node is None:
        oem_node = h.node_add_child(driverinffiles_node, oem_inf)

    h.node_set_value(oem_node, {"key": "", "t": 7, "value": encode_multi_sz([package_dir])})
    h.node_set_value(oem_node, {"key": "Active", "t": 1, "value": encode_utf16le(package_dir)})
    if install_sections:
        h.node_set_value(oem_node, {"key": "Configurations", "t": 7, "value": encode_multi_sz(install_sections)})


_DRIVERPACKAGE_VERSION_HEADER = bytes.fromhex("00 ff 00 00 00 00 00 00")


def _driver_ver_parts(driver_ver):
    """
    Split an INF DriverVer string ("MM/DD/YYYY,W.X.Y.Z") into its date and
    its four dotted version segments. Returns (datetime_or_None,
    [W, X, Y, Z]_as_ints_or_None). Missing/unparseable segments come back
    as None so the caller can fall back to zero per-field.
    """
    if not driver_ver or ',' not in driver_ver:
        return None, [None] * 4
    date_part, _, version_part = driver_ver.partition(',')
    try:
        date = datetime.strptime(date_part.strip(), '%m/%d/%Y')
    except ValueError:
        date = None
    segments = version_part.strip().split('.')
    segments = (segments + [None] * 4)[:4]
    parts = []
    for seg in segments:
        try:
            parts.append(int(seg))
        except (TypeError, ValueError):
            parts.append(None)
    return date, parts


def build_driverpackage_version_blob(class_guid, driver_ver=None):
    """
    Reconstruction of DriverPackages\\{pkg}\\Version (REG_BINARY): 8-byte
    header + 16-byte binary ClassGUID + a 24-byte trailer encoding the INF's
    DriverVer: an 8-byte Windows FILETIME for the date, then four uint16
    fields for W.X.Y.Z in *reverse* order (Z, Y, X, W), then 8 zero bytes.

    Found by decoding what a previous version of this function treated as a
    fixed "class-level constant" trailer, reused verbatim for every driver:
    it decoded to exactly the date/version of whatever reference driver was
    originally captured to build the template (2025-04-23, 100.101.104.27800),
    and Windows' live PnP install reads it, stamping that same stale
    date/version onto every driver's DriverVersion/DriverDate in
    Control\\Class\\{GUID}\\NNNN regardless of the actual driver being
    installed. The Y/X/W uint16s were initially miscategorized as unrelated
    truncated string data because 104/101/100 happen to equal the ASCII
    codes for 'h'/'e'/'d' - confirmed as real version fields by checking a
    fixed version's actual Device Manager display (W.X.Y showed as 0.0.0
    until these were filled in).
    """
    date, (w, x, y, z) = _driver_ver_parts(driver_ver)
    filetime_bytes = _filetime(date) if date else bytes(8)
    version_fields = b''.join(struct.pack('<H', v & 0xFFFF) if v is not None else bytes(2) for v in (z, y, x, w))
    trailer = filetime_bytes + version_fields + bytes(8)
    return _DRIVERPACKAGE_VERSION_HEADER + guid_to_binary(class_guid) + trailer


def _filetime(date):
    """Windows FILETIME (8 bytes LE): 100ns intervals since 1601-01-01 UTC."""
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    delta = date.replace(tzinfo=timezone.utc) - epoch
    return struct.pack('<Q', int(delta.total_seconds() * 10_000_000))


def inject_driver_package(h, driverpackages_node, package_dir, oem_inf, driver_data, driver_source_path):
    """
    Populate DriverDatabase\\DriverPackages\\{package_dir}\\ - the offline
    driver-package metadata cache DISM builds for boot-critical drivers.
    """
    pkg_node = h.node_get_child(driverpackages_node, package_dir)
    if pkg_node is None:
        pkg_node = h.node_add_child(driverpackages_node, package_dir)

    class_guid = driver_data.get('class_guid') or ''
    inf_name = f"{driver_data['inf_name']}.inf"

    values = [
        {"key": "Provider", "t": 1, "value": encode_utf16le(driver_data.get('provider', ''))},
        {"key": "InfName", "t": 1, "value": encode_utf16le(inf_name)},
        {"key": "OemPath", "t": 1, "value": encode_utf16le(driver_source_path or '')},
        {"key": "SignerName", "t": 1, "value": encode_utf16le("Microsoft Windows Hardware Compatibility Publisher")},
        {"key": "Catalog", "t": 1, "value": encode_utf16le(driver_data.get('catalog_file', ''))},
        {"key": "SignerScore", "t": 4, "value": struct.pack('<I', 0x0d000005)},
        {"key": "StatusFlags", "t": 4, "value": struct.pack('<I', 0x00000012)},
        {"key": "", "t": 1, "value": encode_utf16le(oem_inf)},
    ]
    if class_guid:
        version_blob = build_driverpackage_version_blob(class_guid, driver_data.get('driver_ver'))
        values.append({"key": "Version", "t": 3, "value": version_blob})

    for val in values:
        h.node_set_value(pkg_node, val)

    service_config = driver_data.get('service')
    if service_config:
        install_section = service_config['install_section']
        service_name = service_config['name']

        config_node = ensure_child_path(h, pkg_node, f"Configurations\\{install_section}")
        h.node_set_value(config_node, {"key": "Service", "t": 1, "value": encode_utf16le(service_name)})
        h.node_set_value(config_node, {"key": "ConfigScope", "t": 4, "value": struct.pack('<I', 7)})
        h.node_set_value(config_node, {"key": "ConfigFlags", "t": 4, "value": struct.pack('<I', 0)})

        # .HW-section AddReg (interrupt policy, etc.) mirrors under .../Device
        device_node = h.node_add_child(config_node, "Device")
        inject_addreg_values(h, device_node, driver_data.get('hw_addreg', []))

        # Service-install-section AddReg mirrors under .../Services\{name}\Parameters
        services_mirror = ensure_child_path(h, config_node, f"Services\\{service_name}")
        inject_addreg_values(h, services_mirror, service_config.get('params_addreg', []))

    # Descriptors\{bus}\{device_id}\ - one per hardware ID, referencing tokens
    # (not resolved values - see Strings below) exactly as DISM stores them.
    hw_entries = driver_data.get('hardware_id_entries', [])
    if hw_entries:
        descriptors_node = h.node_add_child(pkg_node, "Descriptors")
        referenced_tokens = set()

        for entry in hw_entries:
            hw_id = entry['hw_id']
            bus_type = hw_id.split('\\')[0] if '\\' in hw_id else 'PCI'
            device_id = hw_id.split('\\', 1)[1] if '\\' in hw_id else hw_id

            bus_node = h.node_get_child(descriptors_node, bus_type)
            if bus_node is None:
                bus_node = h.node_add_child(descriptors_node, bus_type)

            dev_node = h.node_get_child(bus_node, device_id)
            if dev_node is None:
                dev_node = h.node_add_child(bus_node, device_id)

            vendor_token = entry.get('vendor_token', '')
            desc_token = entry.get('device_desc_token', '')
            h.node_set_value(dev_node, {"key": "Configuration", "t": 1, "value": encode_utf16le(entry.get('install_section') or '')})
            h.node_set_value(dev_node, {"key": "Manufacturer", "t": 1, "value": encode_utf16le(f"%{vendor_token}%")})
            h.node_set_value(dev_node, {"key": "Description", "t": 1, "value": encode_utf16le(f"%{desc_token}%")})

            referenced_tokens.add(vendor_token)
            referenced_tokens.add(desc_token)

        # Strings\ - only the tokens actually referenced by Descriptors above
        inf_strings = driver_data.get('strings', {})
        referenced_tokens.discard('')
        if referenced_tokens:
            strings_node = h.node_add_child(pkg_node, "Strings")
            for token in referenced_tokens:
                if token in inf_strings:
                    h.node_set_value(strings_node, {"key": token, "t": 1, "value": encode_utf16le(inf_strings[token])})


def _guestfish_download_file(image_path, remote_path, local_path):
    cmd = f"""
run
mount-options remove_hiberfile,force /dev/sda2 /
download {remote_path} {local_path}
umount /
"""
    result = subprocess.run(['guestfish', '--rw', '-a', str(image_path)], input=cmd, text=True, capture_output=True)
    if result.returncode != 0:
        print(f"  ✗ Failed to extract {remote_path}: {result.stderr}")
        return False
    return True


def _guestfish_upload_file(image_path, local_path, remote_path):
    cmd = f"""
run
mount-options remove_hiberfile,force /dev/sda2 /
upload {local_path} {remote_path}
umount /
"""
    result = subprocess.run(['guestfish', '--rw', '-a', str(image_path)], input=cmd, text=True, capture_output=True)
    if result.returncode != 0:
        print(f"  ✗ Failed to upload {remote_path}: {result.stderr}")
        return False
    return True


def inject_registry_to_image(image_path, driver_data, oem_inf, package_dir, driver_source_path=''):
    """
    Extract registry, inject driver entries, and upload back to image.

    This is the high-level function that orchestrates the complete registry
    injection. Confirmed against a real DISM capture: a non-boot-critical
    (PnP-only) driver gets ZERO registry footprint from offline injection -
    only file placement. So everything below DriverDatabase/PnpLockdownFiles
    is gated on is_boot_critical; non-boot-critical drivers return early.
    """
    is_boot_critical = bool(driver_data.get('service') and driver_data['service']['start'] == 0)

    print("[Registry] Extracting SYSTEM hive from image...")

    with tempfile.TemporaryDirectory() as tmpdir:
        system_hive = os.path.join(tmpdir, "SYSTEM")

        if not _guestfish_download_file(image_path, "/Windows/System32/config/SYSTEM", system_hive):
            return False
        print("  ✓ SYSTEM hive extracted")

        print("[Registry] Modifying SYSTEM hive...")
        try:
            h = hivex.Hivex(system_hive, write=True)

            root = h.root()
            cs001 = h.node_get_child(root, "ControlSet001")
            services = h.node_get_child(cs001, "Services")

            # Confirmed from a real DISM capture: netkvm (Start=3, DEMAND_START)
            # has an AddService section in its INF just like the boot-critical
            # drivers do, yet DISM creates NO Services\netkvm key offline at
            # all - service registration itself only happens for boot-critical
            # drivers at offline-injection time; PnP creates it later for
            # everything else.
            if is_boot_critical and driver_data.get('service'):
                service_config = driver_data['service']
                tag = None

                if service_config['group']:
                    control = h.node_get_child(cs001, "Control")
                    grouporder = h.node_get_child(control, "GroupOrderList")
                    tag = allocate_group_tag(h, grouporder, service_config['group'])

                inject_service_registry(h, services, service_config, oem_inf, tag)
                print(f"  ✓ Service '{service_config['name']}' registered")

                inject_eventlog_registry(h, cs001, service_config['name'], service_config.get('eventlog_addreg', []))

                if tag is not None and service_config['group']:
                    update_group_order_list(h, grouporder, service_config['group'], tag)

            if is_boot_critical and driver_data.get('hardware_ids'):
                driverdb = h.node_get_child(root, "DriverDatabase")
                if driverdb is None:
                    driverdb = h.node_add_child(root, "DriverDatabase")

                deviceids = h.node_get_child(driverdb, "DeviceIds")
                if deviceids is None:
                    deviceids = h.node_add_child(driverdb, "DeviceIds")

                inject_device_ids(h, deviceids, driver_data['hardware_ids'], oem_inf)
                print(f"  ✓ {len(driver_data['hardware_ids'])} device IDs mapped")

                class_guid = driver_data.get('class_guid')
                if class_guid:
                    inject_class_catalog_entry(h, deviceids, class_guid.lower(), oem_inf)

                driverinffiles = h.node_get_child(driverdb, "DriverInfFiles")
                if driverinffiles is None:
                    driverinffiles = h.node_add_child(driverdb, "DriverInfFiles")

                install_sections = [driver_data['service']['install_section']] if driver_data.get('service') else []
                inject_driverinffiles_entry(h, driverinffiles, oem_inf, package_dir, install_sections)
                print(f"  ✓ DriverInfFiles\\{oem_inf} -> {package_dir}")

                driverpackages = h.node_get_child(driverdb, "DriverPackages")
                if driverpackages is None:
                    driverpackages = h.node_add_child(driverdb, "DriverPackages")
                inject_driver_package(h, driverpackages, package_dir, oem_inf, driver_data, driver_source_path)
                print(f"  ✓ DriverPackages\\{package_dir} populated")

                oem_number = int(re.search(r'\d+', oem_inf).group())
                update_oeminfmap_bit(h, driverdb, oem_number)
                print(f"  ✓ OemInfMap bit {oem_number} set")

            h.commit(system_hive)
            del h  # Close hivex handle
            print("  ✓ Registry modifications committed")

        except Exception as e:
            import traceback
            print(f"  ✗ Registry modification failed: {e}")
            traceback.print_exc()
            return False

        print("[Registry] Uploading modified SYSTEM hive...")
        if not _guestfish_upload_file(image_path, system_hive, "/Windows/System32/config/SYSTEM"):
            return False
        print("  ✓ SYSTEM hive uploaded")

    if is_boot_critical:
        if not inject_pnplockdown_to_image(image_path, driver_data, oem_inf, package_dir):
            return False
    elif driver_data.get('hardware_ids'):
        # Non-boot-critical PnP drivers (e.g. netkvm) get their DriverDatabase
        # registration in a separate DRIVERS hive, not SYSTEM - see
        # inject_drivers_hive_to_image() for why.
        if not inject_drivers_hive_to_image(image_path, driver_data, oem_inf, package_dir, driver_source_path):
            return False

    return True


def inject_pnplockdown_registry(h_soft, driver_data, oem_inf, package_dir):
    """
    HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\PnpLockdownFiles:
    protects the boot-critical driver's System32\\drivers copy. Confirmed from
    a real DISM capture to be the ONLY thing DISM writes to the SOFTWARE hive
    when injecting a driver.
    """
    root = h_soft.root()
    lockdown_root = ensure_child_path(
        h_soft, root, "Microsoft\\Windows\\CurrentVersion\\Setup\\PnpLockdownFiles"
    )

    inf_name = driver_data['inf_name']
    driver_path_key = f"%SystemRoot%/System32/drivers/{inf_name}.sys"
    entry_node = h_soft.node_get_child(lockdown_root, driver_path_key)
    if entry_node is None:
        entry_node = h_soft.node_add_child(lockdown_root, driver_path_key)

    source_path = f"%SystemRoot%\\System32\\DriverStore\\FileRepository\\{package_dir}\\{inf_name}.sys"

    h_soft.node_set_value(entry_node, {"key": "Owners", "t": 7, "value": encode_multi_sz([oem_inf])})
    h_soft.node_set_value(entry_node, {"key": "Class", "t": 4, "value": struct.pack('<I', 4)})
    h_soft.node_set_value(entry_node, {"key": "Source", "t": 2, "value": encode_utf16le(source_path)})


def inject_pnplockdown_to_image(image_path, driver_data, oem_inf, package_dir):
    """Extract, modify, and upload the SOFTWARE hive for the PnpLockdownFiles entry."""
    print("[Registry] Extracting SOFTWARE hive from image...")

    with tempfile.TemporaryDirectory() as tmpdir:
        software_hive = os.path.join(tmpdir, "SOFTWARE")

        if not _guestfish_download_file(image_path, "/Windows/System32/config/SOFTWARE", software_hive):
            return False
        print("  ✓ SOFTWARE hive extracted")

        print("[Registry] Modifying SOFTWARE hive...")
        try:
            h = hivex.Hivex(software_hive, write=True)
            inject_pnplockdown_registry(h, driver_data, oem_inf, package_dir)
            h.commit(software_hive)
            del h
            print("  ✓ SOFTWARE hive modifications committed")
        except Exception as e:
            import traceback
            print(f"  ✗ SOFTWARE registry modification failed: {e}")
            traceback.print_exc()
            return False

        print("[Registry] Uploading modified SOFTWARE hive...")
        if not _guestfish_upload_file(image_path, software_hive, "/Windows/System32/config/SOFTWARE"):
            return False
        print("  ✓ SOFTWARE hive uploaded")

    return True


def _guestfish_file_exists(image_path, remote_path):
    """Check whether a file exists in the image without mounting read-write."""
    check_cmd = f"""
run
mount-options remove_hiberfile,force /dev/sda2 /
is-file {remote_path}
umount /
"""
    result = subprocess.run(
        ['guestfish', '--rw', '-a', str(image_path)],
        input=check_cmd,
        text=True,
        capture_output=True
    )
    return result.returncode == 0 and result.stdout.strip().lower() == 'true'


def inject_drivers_hive_to_image(image_path, driver_data, oem_inf, package_dir, driver_source_path=''):
    """
    Windows 10+ builds may split non-boot-critical driver-database content
    into a separate HKLM\\DRIVERS hive (Windows\\System32\\config\\DRIVERS),
    distinct from SYSTEM. Confirmed directly against a real DISM capture:
    a PnP-only driver (netkvm) gets its full DriverDatabase\\DeviceIds /
    DriverInfFiles / DriverPackages registration written HERE instead of
    SYSTEM - without it, Windows PnP has no way to match the driver to
    detected hardware, so it never auto-installs (confirmed empirically:
    injected netkvm never bound to the VirtIO NIC until this was added).
    Boot-critical drivers get nothing here (confirmed empty for viostor/vioscsi).

    Not all Windows builds have this hive split, so this is a no-op if the
    file doesn't exist - never invent it.
    """
    if not _guestfish_file_exists(image_path, "/Windows/System32/config/DRIVERS"):
        print("[Registry] No separate DRIVERS hive on this image - skipping")
        return True

    print("[Registry] Extracting DRIVERS hive from image...")

    with tempfile.TemporaryDirectory() as tmpdir:
        drivers_hive = os.path.join(tmpdir, "DRIVERS")

        if not _guestfish_download_file(image_path, "/Windows/System32/config/DRIVERS", drivers_hive):
            return False
        print("  ✓ DRIVERS hive extracted")

        print("[Registry] Modifying DRIVERS hive...")
        try:
            h = hivex.Hivex(drivers_hive, write=True)
            root = h.root()

            driverdb = h.node_get_child(root, "DriverDatabase")
            if driverdb is None:
                driverdb = h.node_add_child(root, "DriverDatabase")

            deviceids = h.node_get_child(driverdb, "DeviceIds")
            if deviceids is None:
                deviceids = h.node_add_child(driverdb, "DeviceIds")
            inject_device_ids(h, deviceids, driver_data.get('hardware_ids', []), oem_inf)
            print(f"  ✓ {len(driver_data.get('hardware_ids', []))} device IDs mapped (DRIVERS hive)")

            driverinffiles = h.node_get_child(driverdb, "DriverInfFiles")
            if driverinffiles is None:
                driverinffiles = h.node_add_child(driverdb, "DriverInfFiles")
            # Confirmed: the DRIVERS-hive DriverInfFiles entry has only the
            # default value + Active - no Configurations, unlike SYSTEM's.
            inject_driverinffiles_entry(h, driverinffiles, oem_inf, package_dir, [])
            print(f"  ✓ DriverInfFiles\\{oem_inf} -> {package_dir} (DRIVERS hive)")

            driverpackages = h.node_get_child(driverdb, "DriverPackages")
            if driverpackages is None:
                driverpackages = h.node_add_child(driverdb, "DriverPackages")
            inject_driver_package(h, driverpackages, package_dir, oem_inf, driver_data, driver_source_path)
            print(f"  ✓ DriverPackages\\{package_dir} populated (DRIVERS hive)")

            h.commit(drivers_hive)
            del h
            print("  ✓ DRIVERS hive modifications committed")
        except Exception as e:
            import traceback
            print(f"  ✗ DRIVERS registry modification failed: {e}")
            traceback.print_exc()
            return False

        print("[Registry] Uploading modified DRIVERS hive...")
        if not _guestfish_upload_file(image_path, drivers_hive, "/Windows/System32/config/DRIVERS"):
            return False
        print("  ✓ DRIVERS hive uploaded")

    return True


def inject_service_registry(h_sys, services_node, service_config, oem_inf, tag=None):
    """
    Create Windows service registry entries for the driver.

    This is the CRITICAL part for boot drivers - without proper service
    registration, Windows won't load the driver at boot time.
    """
    service_name = service_config['name']

    # Create service node
    service_node = h_sys.node_add_child(services_node, service_name)

    # Parse service binary path (e.g., %12%\viostor.sys -> System32\drivers\viostor.sys)
    binary_path = service_config['binary'].replace('%12%', 'System32\\drivers')

    # Add service values
    values = [
        {"key": "ImagePath", "t": 2, "value": encode_utf16le(binary_path)},  # REG_EXPAND_SZ
        {"key": "Type", "t": 4, "value": struct.pack('<I', service_config['type'])},
        {"key": "Start", "t": 4, "value": struct.pack('<I', service_config['start'])},
        {"key": "ErrorControl", "t": 4, "value": struct.pack('<I', service_config['error_control'])},
        {"key": "Owners", "t": 7, "value": encode_multi_sz([oem_inf])},  # REG_MULTI_SZ
    ]

    # Add Group if specified (critical for boot drivers)
    if service_config['group']:
        values.append({"key": "Group", "t": 1, "value": encode_utf16le(service_config['group'])})

        # Add Tag if provided (boot order within group)
        if tag:
            values.append({"key": "Tag", "t": 4, "value": struct.pack('<I', tag)})

    for val in values:
        h_sys.node_set_value(service_node, val)

    # Create Parameters subkey (BusType, DmaRemappingCompatible, PnpInterface\5,
    # etc.) generically from the INF's own AddReg directives, instead of
    # guessing driver-specific values from the service name.
    inject_addreg_values(h_sys, service_node, service_config.get('params_addreg', []))

    print(f"  ✓ Created service: {service_name}")
    print(f"    - Start type: {service_config['start']} (0=Boot, 1=System, 2=Auto, 3=Manual)")
    print(f"    - Group: {service_config['group'] or '(none)'}")
    if tag:
        print(f"    - Tag: 0x{tag:02x}")

    return service_node


def inject_eventlog_registry(h_sys, cs001_node, service_name, eventlog_addreg):
    """
    Create Services\\EventLog\\System\\{name}, populated from the INF's
    EventLogSection AddReg directives (EventMessageFile, TypesSupported).
    Only created for boot-critical drivers - DISM does not create this for
    PnP-only drivers at offline-injection time.
    """
    if not eventlog_addreg:
        return None

    eventlog_system = ensure_child_path(h_sys, cs001_node, "Services\\EventLog\\System")
    service_eventlog_node = h_sys.node_add_child(eventlog_system, service_name)
    inject_addreg_values(h_sys, service_eventlog_node, eventlog_addreg)

    print(f"  ✓ Created EventLog registration: Services\\EventLog\\System\\{service_name}")
    return service_eventlog_node


def inject_device_ids(h_sys, deviceids_node, hardware_ids, oem_inf):
    """
    Register PCI/USB/etc device IDs to map hardware to driver INF file.

    This allows Windows PnP to find the right driver when hardware is detected.
    """

    # Group by bus type (PCI, USB, ACPI, etc.)
    by_bus = {}
    for hw_id in hardware_ids:
        bus_type = hw_id.split('\\')[0] if '\\' in hw_id else 'PCI'
        if bus_type not in by_bus:
            by_bus[bus_type] = []
        by_bus[bus_type].append(hw_id)

    # Register each device ID
    for bus_type, ids in by_bus.items():
        bus_node = h_sys.node_get_child(deviceids_node, bus_type)
        if bus_node is None:
            bus_node = h_sys.node_add_child(deviceids_node, bus_type)

        for hw_id in ids:
            device_id = hw_id.split('\\', 1)[1] if '\\' in hw_id else hw_id

            # Create device ID node
            # NOTE: node_get_child returns None if child doesn't exist (doesn't raise exception!)
            dev_node = h_sys.node_get_child(bus_node, device_id)
            if dev_node is None:
                dev_node = h_sys.node_add_child(bus_node, device_id)

            # Priority: 0x02ff = generic match, 0x01ff = specific subsystem match
            priority = bytes([0x01, 0xff, 0x00, 0x00]) if '&SUBSYS' in device_id else bytes([0x02, 0xff, 0x00, 0x00])

            h_sys.node_set_value(dev_node, {
                "key": oem_inf,
                "t": 3,  # REG_BINARY
                "value": priority
            })


def inject_driver_files(image_path, driver_dir, inf_data, package_dir, oem_inf):
    """
    Copy driver files to Windows image using guestfish.

    Files are copied to 3 locations:
    1. System32\\drivers\\ - Boot-critical drivers only (Start=0)
    2. DriverStore\\FileRepository\\{package_dir}\\ - All driver files
    3. Windows\\INF\\oemN.inf - INF registration

    Uses flatpak-spawn to access host's guestfish.
    """
    import subprocess

    driver_dir = Path(driver_dir)
    inf_name = inf_data['inf_name']
    is_boot_critical = inf_data['service'] and inf_data['service']['start'] == 0

    print(f"[File Placement] Copying driver files to image...")
    print(f"  Image: {image_path}")
    print(f"  Package: {package_dir}")
    print(f"  Boot-critical: {is_boot_critical}")
    print("")

    # Build guestfish command script
    # Manual run and mount with read-write
    # Use remove_hiberfile option to handle Windows hibernation
    guestfish_script = f"""
run

# Mount with remove_hiberfile to handle hibernated Windows
mount-options remove_hiberfile,force /dev/sda2 /

# Create DriverStore directory
mkdir-p /Windows/System32/DriverStore/FileRepository/{package_dir}
"""

    # Copy boot-critical driver to System32\drivers
    if is_boot_critical:
        sys_file = f"{inf_name}.sys"
        if (driver_dir / sys_file).exists():
            guestfish_script += f"""
# Copy boot-critical driver to System32\\drivers
upload {driver_dir / sys_file} /Windows/System32/drivers/{sys_file}
"""
            print(f"  ✓ Queued: {sys_file} → System32/drivers/")

    # Copy all source files to DriverStore
    for source_file in inf_data['source_files']:
        source_path = driver_dir / source_file
        if source_path.exists():
            # Resolve symlinks
            real_path = source_path.resolve()
            guestfish_script += f"""
upload {real_path} /Windows/System32/DriverStore/FileRepository/{package_dir}/{source_file}
"""
            print(f"  ✓ Queued: {source_file} → DriverStore/{package_dir}/")
        else:
            print(f"  ⚠ Warning: {source_file} not found, skipping")

    # Copy catalog file if exists
    cat_file = inf_data['catalog_file']
    cat_path = driver_dir / cat_file
    if cat_path.exists():
        real_cat_path = cat_path.resolve()
        guestfish_script += f"""
upload {real_cat_path} /Windows/System32/DriverStore/FileRepository/{package_dir}/{cat_file}
"""
        print(f"  ✓ Queued: {cat_file} → DriverStore/{package_dir}/")

        # Publish the catalog to CatRoot, matching real DISM (confirmed via
        # setupapi.offline.log: "Published catalog 'X.cat' as 'oemN.cat'"
        # for every driver, boot-critical or not - this is the Windows
        # catalog/signature-verification database used at driver-install
        # time, distinct from the DriverStore copy).
        oem_cat = oem_inf.replace('.inf', '.cat')
        catroot_dir = "/Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}"
        guestfish_script += f"""
mkdir-p {catroot_dir}
upload {real_cat_path} {catroot_dir}/{oem_cat}
"""
        print(f"  ✓ Queued: {cat_file} → CatRoot/{{F750E6C3-...}}/{oem_cat}")

    # Copy INF to DriverStore
    inf_source = driver_dir / f"{inf_name}.inf"
    real_inf_path = inf_source.resolve()
    guestfish_script += f"""
upload {real_inf_path} /Windows/System32/DriverStore/FileRepository/{package_dir}/{inf_name}.inf
"""
    print(f"  ✓ Queued: {inf_name}.inf → DriverStore/{package_dir}/")

    # Copy INF to Windows\INF as oemN.inf
    guestfish_script += f"""
upload {real_inf_path} /Windows/INF/{oem_inf}
"""
    print(f"  ✓ Queued: {inf_name}.inf → INF/{oem_inf}")

    # Unmount
    guestfish_script += """
umount /
"""

    print("")
    print("Executing guestfish commands...")

    # Execute guestfish (already on host when called via flatpak-spawn --host python3)
    # Note: Order matters - must be: --rw -a <image> -i
    try:
        result = subprocess.run(
            ['guestfish', '--rw', '-a', str(image_path)],
            input=guestfish_script,
            text=True,
            capture_output=True,
            timeout=300
        )

        if result.returncode != 0:
            print(f"ERROR: guestfish failed")
            print(f"STDOUT: {result.stdout}")
            print(f"STDERR: {result.stderr}")
            return False

        print("  ✓ File placement complete!")
        return True

    except subprocess.TimeoutExpired:
        print("ERROR: guestfish timed out (5 min)")
        return False
    except Exception as e:
        print(f"ERROR: {e}")
        return False


def verify_file_placement(image_path, package_dir, oem_inf, is_boot_critical, inf_name):
    """
    Verify that driver files were copied correctly using guestfish.
    """
    import subprocess

    print("")
    print("[Verification] Checking file placement...")

    verify_script = f"""
run
mount /dev/sda2 /

# Check DriverStore package directory
is-dir /Windows/System32/DriverStore/FileRepository/{package_dir}

# Check OEM INF file
is-file /Windows/INF/{oem_inf}
"""

    if is_boot_critical:
        verify_script += f"""
# Check boot-critical driver in System32/drivers
is-file /Windows/System32/drivers/{inf_name}.sys
"""

    verify_script += """
umount /
"""

    try:
        result = subprocess.run(
            ['guestfish', '--ro', '-a', str(image_path)],
            input=verify_script,
            text=True,
            capture_output=True,
            timeout=60
        )

        # guestfish is-file/is-dir return true/false, we just check no errors
        if result.returncode == 0:
            print("  ✓ All files verified!")
            return True
        else:
            print("  ✗ Verification failed")
            print(f"  {result.stderr}")
            return False

    except Exception as e:
        print(f"  ⚠ Verification error: {e}")
        return False


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Universal Windows Driver Injection')
    parser.add_argument('--driver', required=True, help='Path to driver directory (containing .inf file)')
    parser.add_argument('--image', required=True, help='Path to Windows image (VHDX/qcow2)')
    parser.add_argument('--dry-run', action='store_true', help='Parse INF only, don\'t inject')
    parser.add_argument('--inject-files', action='store_true', help='Inject driver files into image')

    args = parser.parse_args()

    # Find .inf file in driver directory
    driver_dir = Path(args.driver)
    inf_files = list(driver_dir.glob('*.inf'))

    if not inf_files:
        print(f"ERROR: No .inf file found in {driver_dir}")
        sys.exit(1)

    inf_path = inf_files[0]
    print(f"Found INF: {inf_path.name}")
    print("")

    # Parse INF file
    print("Parsing INF file...")
    parser = INFParser(inf_path)

    print(f"Driver: {parser.data.get('provider', 'Unknown')}")
    print(f"Class: {parser.data.get('class', 'Unknown')}")
    print(f"Version: {parser.data.get('driver_ver', 'Unknown')}")
    print(f"Hardware IDs: {len(parser.data['hardware_ids'])}")
    if parser.data['service']:
        print(f"Service: {parser.data['service']['name']}")
        print(f"  Start Type: {parser.data['service']['start']} (0=Boot-critical)")
        print(f"  Load Group: {parser.data['service']['group'] or '(none)'}")
    print(f"Source Files: {len(parser.data['source_files'])}")
    print("")

    if args.dry_run:
        print("Dry run - stopping here.")
        print("")
        print("Parsed data:")
        import json
        print(json.dumps(parser.data, indent=2, default=str))
        return

    if not args.inject_files:
        print("To inject files, use --inject-files flag")
        return

    # Generate DriverStore hash. Microsoft's real algorithm is undocumented
    # and proprietary (confirmed by Microsoft support staff - see
    # groups.google.com/g/microsoft.public.win32.programmer.kernel/c/Kz5g0KSVHkY -
    # and not reproducible from the driver files themselves: reverse-engineering
    # attempts against known DISM-assigned hashes for viostor/vioscsi/netkvm,
    # using PE TimeDateStamp/CheckSum/PDB GUID and raw file hashes, found no
    # match). generate_driverstore_hash() is our own deterministic substitute -
    # it only needs to be unique and stable per driver version, not byte-identical
    # to what real DISM would have assigned.
    driverstore_hash = generate_driverstore_hash(inf_path)

    # Architecture comes from the driver directory itself (e.g.
    # .../viostor/w10/amd64 -> "amd64"), matching how the driver source tree
    # is laid out and how DISM's own package_dir naming reflects the actual
    # target architecture - not something to guess or hardcode.
    arch = driver_dir.name.lower()

    # DISM uses format: drivername.inf_arch_hash
    package_dir = f"{parser.inf_name}.inf_{arch}_{driverstore_hash}"
    print(f"DriverStore package: {package_dir}")
    print("")

    # Determine the next free OEM INF number by scanning the image's actual
    # Windows\INF directory, so injecting multiple drivers in sequence doesn't
    # collide on the same oemN.inf (each call re-reads the image since a
    # prior injection may have just published a new oemN.inf).
    oem_number = get_next_oem_number(args.image)
    oem_inf = f"oem{oem_number}.inf"
    print(f"OEM INF: {oem_inf}")
    print("")

    # File Placement
    print("="*60)
    print("PHASE 1: File Placement")
    print("="*60)
    success = inject_driver_files(
        args.image,
        driver_dir,
        parser.data,
        package_dir,
        oem_inf
    )

    if not success:
        print("")
        print("✗ File placement failed!")
        sys.exit(1)

    # Verify file placement
    is_boot_critical = parser.data['service'] and parser.data['service']['start'] == 0
    verify_file_placement(
        args.image,
        package_dir,
        oem_inf,
        is_boot_critical,
        parser.inf_name
    )

    print("")
    print("="*60)
    print("PHASE 2: Registry Injection")
    print("="*60)

    # Inject registry entries
    success = inject_registry_to_image(
        args.image,
        parser.data,
        oem_inf,
        package_dir,
        driver_source_path=str(driver_dir)
    )

    if not success:
        print("✗ Registry injection failed!")
        sys.exit(1)

    print("")
    print("="*60)
    print("✓ Driver injection complete!")
    print("="*60)
    print(f"Driver: {parser.data['service']['name']}")
    print(f"Package: {package_dir}")
    print(f"OEM INF: {oem_inf}")


if __name__ == '__main__':
    main()
