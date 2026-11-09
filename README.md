# Windows Driver Injection Tool

A command-line tool that injects Windows drivers (VirtIO or otherwise)
directly into an offline Windows disk image, replicating what
`DISM /Add-Driver` does — without needing DISM, Windows, or a running VM.
Built for V2V migration: preparing a Windows VM's disk so it can boot under
KVM/QEMU with VirtIO storage/network before the first boot.

It works from a single INF-driven code path — there is no per-driver
special-casing. Any driver with a standard Windows INF should work,
boot-critical or not, x86 or x64.

## How it works, in short

1. Parses the driver's `.inf` file (custom parser — Windows INFs use
   duplicate keys and encodings that Python's `ConfigParser` can't handle
   correctly).
2. Copies the driver's files into the image at the right locations
   (`System32\drivers` for boot-critical drivers, `DriverStore\FileRepository`
   for all drivers, `Windows\INF\oemN.inf`, and the `CatRoot` catalog store).
3. Writes the registry entries Windows needs to load and PnP-match the
   driver (`Services\...`, `DriverDatabase\DeviceIds`/`DriverInfFiles`/
   `DriverPackages`, `GroupOrderList`, `PnpLockdownFiles`, and the separate
   `DRIVERS` hive some Windows builds use for non-boot-critical drivers).

All of this happens directly on the disk image file via `guestfish`
(filesystem) and `hivex` (registry) — the image is never booted.

## Environment note

If you're running inside a Flatpak sandbox (VS Code Flatpak, etc.), prefix
every command with `flatpak-spawn --host` so it runs against the host's
`guestfish`/`hivex`/QEMU rather than the sandbox's. All examples below
assume this. If you're not in a sandbox, drop the prefix.

## Prerequisites

- `guestfish` (libguestfs)
- Python 3 with the `hivex` module
- The driver's `.inf`/`.sys`/`.cat` files in one directory (the standard
  layout signed driver packages ship in)

## Basic usage

```bash
flatpak-spawn --host python3 inject_driver.py \
    --driver /path/to/driver/directory \
    --image /path/to/windows-disk.qcow2 \
    --inject-files
```

`--driver` points at the directory *containing* the `.inf` file — not the
`.inf` file itself. The tool finds the `.inf` automatically.

### Flags

| Flag | Purpose |
|---|---|
| `--driver PATH` | Directory containing the driver's `.inf` (required) |
| `--image PATH` | Path to the target disk image — VHDX or qcow2 (required) |
| `--dry-run` | Parse the INF and print what was found; make no changes |
| `--inject-files` | Actually perform the injection (file + registry) |

Without `--inject-files`, the tool parses the INF, prints a summary, and
stops — use this to sanity-check a driver before touching an image:

```bash
flatpak-spawn --host python3 inject_driver.py \
    --driver /path/to/driver/directory \
    --image /path/to/windows-disk.qcow2 \
    --dry-run
```

This prints the parsed class, hardware IDs, service configuration, and
source file list, followed by the full parsed data structure as JSON — a
quick way to see whether the parser is reading the INF the way you expect
before committing to an actual injection.

## Picking the right driver build for a target image

Driver packages are normally organized by Windows version and
architecture (e.g. `drivers/viostor/w10/amd64`, `drivers/viostor/2k19/x86`).
Rather than guessing, `detect_target_os.py` inspects the target image's own
registry and tells you which one to use:

```bash
flatpak-spawn --host python3 detect_target_os.py \
    --image /path/to/windows-disk.qcow2 \
    --driver-root /path/to/drivers/viostor
```

Example output:

```
Detected target OS:
  Product Name:      Windows Server 2022 Standard
  Installation Type: Server
  Build Number:      20348
  Architecture:      AMD64

Recommended driver subfolder: 2k22/amd64
  -> Confirmed exists: /path/to/drivers/viostor/2k22/amd64
```

It reads `CurrentBuildNumber` and `InstallationType` from the `SOFTWARE`
hive — build number alone is ambiguous (e.g. build 17763 is both Windows 10
1809 and Server 2019), and `InstallationType` disambiguates it — plus
`PROCESSOR_ARCHITECTURE` from the `SYSTEM` hive. It also correctly handles
Windows 11 images whose registry `ProductName` still misleadingly reads
"Windows 10 Enterprise" (a known Windows quirk), by checking the build
number instead. `--driver-root` is optional; without it, the tool just
prints the detected OS info without checking whether a matching folder
exists on disk.

## Injecting multiple drivers

Run the tool once per driver, against the same image, in any order:

```bash
for driver in viostor vioscsi NetKVM; do
    flatpak-spawn --host python3 inject_driver.py \
        --driver /path/to/drivers/$driver/w10/amd64 \
        --image /path/to/windows-disk.qcow2 \
        --inject-files
done
```

Each run scans the image's actual `Windows\INF` directory to pick the next
free `oemN.inf` number, so drivers injected in sequence never collide —
this also correctly skips numbers already used by inbox drivers on a real
Windows image, not just ones this tool added.

## Listing installed 3rd-party drivers

`list_drivers.py` inventories every OEM driver already present in an
image — useful for pre-migration planning ("what drivers does this VM
have?"), post-injection verification, or debugging.

```bash
# Quick summary table (registry only, fastest)
python3 list_drivers.py --image /path/to/windows-disk.qcow2

# Full metadata — downloads and parses each INF for class, manufacturer,
# provider, and version
python3 list_drivers.py --image /path/to/windows-disk.qcow2 --parse-infs

# Detailed per-driver view
python3 list_drivers.py --image /path/to/windows-disk.qcow2 --parse-infs -v

# Show only non-Microsoft drivers (implies --parse-infs)
python3 list_drivers.py --image /path/to/windows-disk.qcow2 --no-microsoft

# Machine-readable JSON output (implies --parse-infs)
python3 list_drivers.py --image /path/to/windows-disk.qcow2 --json
```

| Flag | Purpose |
|---|---|
| `--image PATH` | Path to the target disk image (required) |
| `--parse-infs` | Download and parse each oem*.inf for full metadata |
| `--verbose`, `-v` | Detailed per-driver output instead of summary table |
| `--no-microsoft` | Filter out Microsoft inbox drivers (implies `--parse-infs`) |
| `--json` | JSON output (implies `--parse-infs`) |

The tool cross-references the on-disk `Windows\INF\oem*.inf` files with
the `DriverDatabase` entries in both the `SYSTEM` and `DRIVERS` registry
hives. Drivers that exist on disk but not in the registry (or vice versa)
are flagged, and boot-critical drivers (Start=0) are tagged `[BOOT]`.

Example output with `--no-microsoft`:

```
Found 21 3rd-party driver(s):

── oem2.inf [BOOT-CRITICAL] ──
  Class:          System {4d36e97d-e325-11ce-bfc1-08002be10318}
  Manufacturer:   VMware, Inc.
  ...
  Service:        vmci (Start=Boot, Group=System Bus Extender)

── oem4.inf ──
  Class:          Net {4d36e972-e325-11ce-bfc1-08002be10318}
  Manufacturer:   VMware, Inc.
  ...

── oem19.inf [BOOT-CRITICAL] ──
  Class:          SCSIAdapter {4D36E97B-E325-11CE-BFC1-08002BE10318}
  Manufacturer:   Red Hat, Inc.
  ...
  Service:        viostor (Start=Boot, Group=SCSI miniport)
```

## Inspecting a specific driver in detail

`show_driver.py` looks up a single driver by name and dumps everything the
image knows about it — the full registry subtree, file listing, hardware
ID matching priority, PnpLockdownFiles, CatRoot presence, and
DriverPackages metadata.

```bash
# Look up by service name
python3 show_driver.py --image /path/to/windows-disk.qcow2 --name viostor

# Look up by OEM INF
python3 show_driver.py --image /path/to/windows-disk.qcow2 --name oem4.inf

# Look up by package prefix
python3 show_driver.py --image /path/to/windows-disk.qcow2 --name vmxnet3

# JSON output
python3 show_driver.py --image /path/to/windows-disk.qcow2 --name netkvm --json
```

The `--name` argument is flexible — it matches against the service name,
OEM INF name, or DriverStore package prefix. If the term is ambiguous,
the script lists all matches; if not found, it lists all available drivers
so you can see what's there.

Example output:

```
══════════════════════════════════════════════════════════════════════
  Driver: viostor [BOOT-CRITICAL]
══════════════════════════════════════════════════════════════════════

  OEM INF:        oem19.inf
  DriverStore:    viostor.inf_amd64_8970a5afdb7f2917

  ── INF Metadata ──
  Class:          SCSIAdapter {4D36E97B-E325-11CE-BFC1-08002BE10318}
  Manufacturer:   Red Hat, Inc.
  Driver date:    04/23/2025
  Driver version: 100.101.104.27800
  Catalog file:   viostor.cat

  ── Service Registry (ControlSet001\Services\viostor) ──
  Group                  REG_SZ           SCSI miniport
  ImagePath              REG_EXPAND_SZ    system32\drivers\viostor.sys
  Start                  REG_DWORD        0x00000000 (0)
  Tag                    REG_DWORD        0x00000021 (33)
  ...

  ── Hardware IDs (DriverDatabase\DeviceIds) ──
  PCI\VEN_1AF4&DEV_1001                     [02ff0000] (compatible)
  PCI\VEN_1AF4&DEV_1001&SUBSYS_00021AF4...  [01ff0000] (exact match)
  ...

  ── DriverStore Files ──
  viostor.cat                                 11.3 KB
  viostor.inf                                  2.9 KB
  viostor.sys                                 63.0 KB

  ── Boot Driver (System32\drivers) ──
  viostor.sys                                  63.0 KB

  ── CatRoot ──
  {F750E6C3-...}\oem19.cat: present

  ── PnpLockdownFiles ──
  Owners       REG_MULTI_SZ     oem19.inf
  Source       REG_EXPAND_SZ    %SystemRoot%\...\viostor.sys

  ── DriverPackages Registry ──
  Provider     REG_SZ           Red Hat, Inc.
  SignerName   REG_SZ           Microsoft Windows Hardware Compatibility Publisher
  ...
```

## Verifying the result

The tool doesn't boot the image itself. To confirm a driver actually
works, boot the image under QEMU with the matching VirtIO device attached
and check Device Manager. `boot_test/*.sh` has working examples — e.g.
`boot_test/boot_intensive_test.sh` boots a system disk on `virtio-blk-pci`,
a data disk on `virtio-scsi-pci`, a NIC on `virtio-net-pci`, plus several
other VirtIO device types, and is a good template to copy for your own
device combination. The general pattern for any driver: attach the QEMU
device whose hardware ID matches the driver's `[Manufacturer]` section,
boot, and check the corresponding Device Manager category for "this device
is working properly" with no error icon.

**Avoid `-machine q35`** when boot-testing a boot-critical storage driver
unless you've specifically validated your target OS/QEMU combination
against it — see Known Limitations below.

## Known limitations

- **Re-injecting onto a non-pristine image can fail.** If the target image
  already has a `Services\<name>` registry key for the driver you're
  injecting (a previous manual install, inbox support, or a prior run of
  this tool), injection currently crashes with
  `RuntimeError: File exists` instead of handling it gracefully. Pristine
  or freshly-cleaned images work fine. `boot_test/cleanup_virtio_remnants.py`
  shows the kind of registry/file cleanup needed to recover an image with
  leftover entries (written for one specific case — not a general tool,
  but a useful reference for what to look for: `Services\<name>`,
  `Services\EventLog\System\<name>`, `GroupOrderList` tags,
  `PnpLockdownFiles` entries, and the driver's `.sys` in `System32\drivers`).

- **The DriverStore package hash doesn't match real DISM's.** Microsoft's
  actual hashing algorithm for `DriverStore\FileRepository\{name}.inf_{arch}_{hash}`
  is undocumented and not publicly known to be derived from the driver
  files at all (confirmed by Microsoft support staff on a public forum, and
  independently by trying to reverse-engineer it from known DISM-assigned
  hashes here — no match found). This tool generates its own deterministic
  hash (MD5 of the INF content) instead. This is cosmetic only — it doesn't
  affect boot or PnP correctness, just means the folder name won't match
  what real DISM would have produced for the same driver.

- **Windows Fast Startup can block re-mounting a test image.** If you boot
  a test image, shut it down, and then get
  `The disk contains an unclean file system` from `guestfish` on the next
  mount attempt, Fast Startup is almost certainly why (it hibernates the
  kernel session even on a normal "Shut Down", leaving NTFS flagged as
  still-mounted). Fix once per image: boot it, run
  `powercfg /h off` in an elevated Command Prompt, then a real
  `shutdown /s /t 0`. After that, the image mounts cleanly going forward.
  `remove_hiberfile`/`force` `guestfish` mount options do **not** fix this —
  only actually disabling Fast Startup inside the guest does.

- **`-machine q35` and boot-critical storage drivers don't always mix.**
  On one Windows 10 x86 test image, `-machine q35` caused a deterministic
  `INACCESSIBLE_BOOT_DEVICE` BSOD regardless of registry content — the same
  injected disk booted cleanly with the default machine type (i440fx/pc)
  and failed every time under q35, with nothing else changed. On a
  different Windows Server 2022 x64 image, q35 was merely flaky (occasional
  boot-manager failures unrelated to the injected drivers, most attempts
  succeeded). If you need q35, validate your specific target OS/QEMU
  version combination before relying on it.
