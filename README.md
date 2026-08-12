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

## Prerequisites

- `guestfish` (libguestfs)
- Python 3 with the `hivex` module
- The driver's `.inf`/`.sys`/`.cat` files in one directory (the standard
  layout signed driver packages ship in)

## Basic usage

```bash
python3 inject_driver.py \
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
python3 inject_driver.py \
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
python3 detect_target_os.py \
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
    python3 inject_driver.py \
        --driver /path/to/drivers/$driver/w10/amd64 \
        --image /path/to/windows-disk.qcow2 \
        --inject-files
done
```

Each run scans the image's actual `Windows\INF` directory to pick the next
free `oemN.inf` number, so drivers injected in sequence never collide —
this also correctly skips numbers already used by inbox drivers on a real
Windows image, not just ones this tool added.

## Verifying the result

The tool doesn't boot the image itself. To confirm a driver actually
works, boot the image under QEMU with the matching VirtIO device attached
and check Device Manager — attach the QEMU device whose hardware ID
matches the driver's `[Manufacturer]` section (e.g. `virtio-blk-pci` for
`viostor`, `virtio-scsi-pci` for `vioscsi`, `virtio-net-pci` for `netkvm`),
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
  or freshly-cleaned images work fine. If you hit this, the fix is to
  remove the leftover `Services\<name>` key (and its
  `Services\EventLog\System\<name>` subkey, any stale `GroupOrderList`
  tag referencing it, and any `PnpLockdownFiles` entry for the driver's
  `.sys`) from the image's registry before re-injecting.

- **The DriverStore package hash doesn't match real DISM's.** Microsoft's
  actual hashing algorithm for `DriverStore\FileRepository\{name}.inf_{arch}_{hash}`
  is undocumented and not publicly known to be derived from the driver
  files at all (confirmed by Microsoft support staff on a public forum, and
  independently by trying to reverse-engineer it from known DISM-assigned
  hashes — no match found). This tool generates its own deterministic hash
  (MD5 of the INF content) instead. This is cosmetic only — it doesn't
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
