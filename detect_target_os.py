#!/usr/bin/env python3
"""
Inspect a Windows disk image's registry and report which driver subfolder
(from the signed-win-drivers layout, e.g. drivers/viostor/{winver}/{arch})
matches it, instead of guessing or hardcoding one architecture.

Windows build numbers alone are ambiguous between client and server (e.g.
build 17763 is both Windows 10 1809 and Server 2019) - InstallationType
from the registry disambiguates them. Bitness comes straight from
PROCESSOR_ARCHITECTURE rather than inferring it from directory names, which
can vary by locale.

Usage:
    python3 detect_target_os.py --image /path/to/disk.vhdx
"""
import argparse
import subprocess
import tempfile
from pathlib import Path

import hivex

# NT build number -> driver-tree folder name, kept separate for Client vs
# Server since several builds are numerically identical between the two
# (1607/2016=14393, 1809/2019=17763, 24H2/2025~=26100).
CLIENT_BUILDS = {
    2600: 'xp',
    7600: 'w7', 7601: 'w7',
    9200: 'w8',
    9600: 'w8.1',
}
SERVER_BUILDS = {
    3790: '2k3',
    6001: '2k8', 6002: '2k8',
    7600: '2k8R2', 7601: '2k8R2',
    9200: '2k12',
    9600: '2k12R2',
    14393: '2k16',
    17763: '2k19',
    20348: '2k22',
}
# Anything NT 10.0 not in the tables above: client splits at build 22000
# (Windows 11), server 2025 is anything above 2k22's build.
CLIENT_W10_MAX_BUILD = 22000
SERVER_2K22_BUILD = 20348


def guestfish_read_only(image_path, commands):
    cmd = f"run\n{commands}\n"
    result = subprocess.run(
        ['guestfish', '--ro', '-a', str(image_path)],
        input=cmd, text=True, capture_output=True
    )
    return result


def find_windows_partition(image_path):
    """Probe each partition for Windows\\System32\\config\\SOFTWARE."""
    result = guestfish_read_only(image_path, "list-filesystems")
    if result.returncode != 0:
        raise RuntimeError(f"list-filesystems failed: {result.stderr}")

    partitions = [line.split(':')[0].strip() for line in result.stdout.splitlines() if line.strip()]
    for part in partitions:
        check = guestfish_read_only(
            image_path,
            f"mount-ro {part} /\n"
            f"is-file /Windows/System32/config/SOFTWARE\n"
        )
        if check.returncode == 0 and check.stdout.strip().splitlines()[-1] == 'true':
            return part
    raise RuntimeError(f"No Windows partition found among: {partitions}")


def download_hive(image_path, partition, remote_path, local_path):
    result = guestfish_read_only(
        image_path,
        f"mount-ro {partition} /\n"
        f"download {remote_path} {local_path}\n"
    )
    if result.returncode != 0:
        raise RuntimeError(f"Failed to download {remote_path}: {result.stderr}")


def read_value(h, node, name, default=None):
    try:
        val = h.node_get_value(node, name)
    except Exception:
        return default
    vtype, _vlen = h.value_type(val)
    if vtype in (1, 2):  # REG_SZ, REG_EXPAND_SZ
        return h.value_string(val)
    if vtype == 4:  # REG_DWORD
        return h.value_dword(val)
    return default


def detect_windows_version(software_hive_path):
    h = hivex.Hivex(software_hive_path)
    root = h.root()
    node = root
    for part in ['Microsoft', 'Windows NT', 'CurrentVersion']:
        node = h.node_get_child(node, part)
        if node is None:
            raise RuntimeError(f"Registry path Microsoft\\Windows NT\\CurrentVersion not found (missing {part})")

    product_name = read_value(h, node, 'ProductName', 'Unknown')
    build = read_value(h, node, 'CurrentBuildNumber', '0')
    build = int(build) if isinstance(build, str) else build
    display_version = read_value(h, node, 'DisplayVersion') or read_value(h, node, 'ReleaseId', '')
    installation_type = read_value(h, node, 'InstallationType', 'Client')
    current_version = read_value(h, node, 'CurrentVersion', '')

    return {
        'product_name': product_name,
        'build': build,
        'display_version': display_version,
        'installation_type': installation_type,
        'current_version': current_version,
    }


def detect_bitness(system_hive_path):
    h = hivex.Hivex(system_hive_path)
    root = h.root()
    # ControlSet001 is used consistently elsewhere in this project rather
    # than resolving Select\Current, matching the rest of the codebase.
    node = root
    for part in ['ControlSet001', 'Control', 'Session Manager', 'Environment']:
        child = h.node_get_child(node, part)
        if child is None:
            return 'unknown'
        node = child
    arch = read_value(h, node, 'PROCESSOR_ARCHITECTURE', 'unknown')
    return arch


def pick_driver_folder(version_info, arch):
    is_server = version_info['installation_type'].lower().startswith('server')
    build = version_info['build']

    if is_server:
        folder = SERVER_BUILDS.get(build)
        if folder is None:
            folder = '2k25' if build > SERVER_2K22_BUILD else f'unknown-server-build-{build}'
    else:
        folder = CLIENT_BUILDS.get(build)
        if folder is None:
            if build >= CLIENT_W10_MAX_BUILD:
                folder = 'w11'
            elif build >= 10240:
                folder = 'w10'
            else:
                folder = f'unknown-client-build-{build}'

    arch_folder = {'AMD64': 'amd64', 'X86': 'x86', 'ARM64': 'arm64'}.get(arch.upper(), arch.lower())
    return folder, arch_folder


def main():
    parser = argparse.ArgumentParser(description='Detect Windows version/bitness and the matching driver subfolder')
    parser.add_argument('--image', required=True, help='Path to Windows disk image (VHDX/qcow2)')
    parser.add_argument('--driver-root', help='Optional: drivers/<name> root to also validate the folder exists, e.g. drivers/viostor')
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmpdir:
        software_hive = f"{tmpdir}/SOFTWARE"
        system_hive = f"{tmpdir}/SYSTEM"

        print(f"Probing partitions in {args.image}...")
        partition = find_windows_partition(args.image)
        print(f"  Windows found on {partition}")

        download_hive(args.image, partition, "/Windows/System32/config/SOFTWARE", software_hive)
        download_hive(args.image, partition, "/Windows/System32/config/SYSTEM", system_hive)

        version_info = detect_windows_version(software_hive)
        arch = detect_bitness(system_hive)
        folder, arch_folder = pick_driver_folder(version_info, arch)

        print("")
        print("Detected target OS:")
        print(f"  Product Name:      {version_info['product_name']}")
        print(f"  Installation Type: {version_info['installation_type']}")
        print(f"  Current Version:   {version_info['current_version']}")
        print(f"  Display/Release:   {version_info['display_version']}")
        print(f"  Build Number:      {version_info['build']}")
        print(f"  Architecture:      {arch}")
        print("")
        print(f"Recommended driver subfolder: {folder}/{arch_folder}")

        if args.driver_root:
            candidate = Path(args.driver_root) / folder / arch_folder
            if candidate.is_dir():
                print(f"  -> Confirmed exists: {candidate}")
            else:
                print(f"  -> WARNING: {candidate} does not exist on disk")


if __name__ == '__main__':
    main()
