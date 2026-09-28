# VexZygisk

**English** · [简体中文](README.zh-CN.md)

VexZygisk is a standalone implementation of Zygisk for KernelSU and APatch, based on ReZygisk.

The codebase has been rewritten to C entirely, bringing not only a much cleaner codebase that is easier to follow, but also lighter binaries that are also faster. Custom linkers also have been introduced to future-proof VexZygisk against future detections: standard Zygisk modules are mapped by the built-in csoloader instead of the system linker, defeating linker-based detection on that path, while Zygisk Next modules keep loading through the system linker as their contract expects.

The project builds for **one root solution at a time**: the KernelSU flavour and the APatch flavour are separate archives produced by the same CI run, and each one carries only its own backend — no traces of the other root solution ship inside.

## Why?

The latest releases of Zygisk Next are not open-source, reserving entirely the code for its developers. Not only does that limit our ability to contribute to the project, but also impossibilities the audit of the code, which is a major security concern, as Zygisk Next is a module that runs with superuser (root) privileges, having access to the entire system.

The Zygisk Next developers are famous and trusted in the Android community, however, this doesn't mean that the code is not malicious or vulnerable. There may be good reasons to keep it closed-source, but this project takes the opposite view.

## Advantages

- FOSS (Forever)
- Zygisk Next module support, companions and the `pltHook` contract included
- KernelSU **and** APatch support, as dedicated builds
- Denylist handled by reverting the mounts in the hidden process itself, with the cached clean namespace as the fallback
- The traces a revert cannot reach are hidden as well: the module libraries a hidden process still has mapped, and the mount line bionic keeps in one static buffer
- HyperOS runtime support: modules that register through the spawner are told when an app is specialized
- Starts from an LKM: a late-load session, or a restarted monitor, claims the targets that are already running instead of waiting for the next fork

## Root solution support

Each archive targets exactly one root solution and refuses to install from anything else:

| Archive | Root solution | Install from |
|---------|---------------|--------------|
| `VexZygisk-<ver>-release.zip` | KernelSU | KernelSU app |
| `VexZygisk-APatch-<ver>-release.zip` | APatch | APatch app |

- The KernelSU flavour talks to the KernelSU kernel interface directly (ioctl based) and requires a recent kernel and ksud.
- The APatch flavour reads the `apd` package configuration (`/data/adb/ap/package_config`) for root grants and the denylist, and recognises both the `me.bmax.apatch` and `me.yuki.folk` managers. It needs a reasonably recent APatch (`APATCH_VER_CODE >= 10762`).
- The APatch archive ships its own `sepolicy.rule` written against the `su` domain (APatch builds on magiskpolicy), while the KernelSU one uses the `ksu` domain.

## Mount handling

Revert-only is the default mount mode, and it is applied to the process being
hidden rather than to the zygote.

A denylisted process is given a private copy of the mount tree and the root
traces are detached from that copy. Detaching rather than unmounting matters:
a metamodule overlay carries the root solution's source name and can cover
system paths — `framework` and provider resources among them — so an unmount
that reaches the filesystem leaves WebView resolving through a path its own
mountinfo still reports as overlaid, and it fails to initialize. The detach
removes the same mounts from the process's view without tearing anything down.
The zygote and the processes that are not being hidden keep their mounts, so a
metamodule's themes and overlays stay visible to the apps that rely on them, and
each hidden process ends up holding a namespace object of its own — the same
shape a normal app has, rather than one shared with every other hidden app.

`webview_zygote` is the one process that is cleaned without ever being on the
denylist. It execs into the real child zygote and every WebView sandboxed
renderer inherits whatever namespace it holds, so it is switched into the cached
clean namespace instead of being reverted in place: an unmount running inside it
would reach processes no revert was meant for.

Reverting out of the zygote instead is what used to break those modules: the
mounts would go away for **every** process forked afterwards, hidden or not.

A metamodule owns all module mounting on both KernelSU and APatch, and what it
hangs there is indistinguishable from a root trace to the selection. Applying
the revert only to the processes being hidden is what covers that — the
selection itself does not have to tell them apart.

When the revert cannot be applied — an exact `/product` mount is among the
traces, which some ROMs overlay with zygote resources, or some of them refuse
to come down — the process is hidden the namespace way instead, by switching it
into a cached clean namespace.

Neither mode reaches everything. Two traces stay inside a hidden process, and
both are only final once the modules have run:

- the module libraries still mapped into it, each naming its own file in
  `/proc/self/maps`. Those mappings are replaced by anonymous copies of the same
  bytes at the same address, so the library keeps running from where it was and
  the name is gone — the Zygisk Next libraries included, which the loader hands
  over as memfds and which no path under `/data` describes.
- the mount line bionic parses into a single static buffer. The zygote reads it
  while it still carries the module mounts and every application forked from it
  inherits it, so a process whose tree was cleaned can still read the traces out
  of its own libc. Parsing a mount table once the tree is already the clean one
  is what replaces its content.

Dropping a marker next to the module selects that namespace path for every
process, without a rebuild:

```sh
touch /data/adb/rezygisk/disable-revert   # or /data/adb/modules/rezygisk/disable-revert
```

## Late load

KernelSU can be injected into a system that is already running — the temporary
root flows that leave the bootloader locked. KernelSU does not exist while
`post-fs-data` passes in that session, so the module's own stage never runs, no
monitor is started, and every Zygisk module stays dead while the manager keeps
listing the module as installed.

The KernelSU archive therefore installs itself into `late-load.d` as well, the
stage `ksud late-load` runs straight after the injection. The monitor it starts
claims the targets that are already running — the zygote and the HyperOS spawner
— instead of waiting for the next fork, and attaches to them rather than killing
them so init respawns them. A soft reboot replays the boot stages but keeps the
injected KernelSU, so the same stage is what brings the monitor back, and it
leaves an already running one alone.

Only the KernelSU flavour ships this. APatch has no comparable stage, so the
APatch archive removes any copy it finds rather than installing one.

## Zygisk Next support

VexZygisk speaks the Zygisk Next API, so modules written against it — recent LSPosed builds among them — can load through it.

- Modules are listed through `zn_modules.txt`, with per-target resolution and optional companions. A companion is forked from the daemon so it keeps the daemon's privileged SELinux domain instead of the restricted domain of the process that loaded the module.
- Module libraries are handed over as memfds rather than descriptors of the files themselves, so an unprivileged target can load them without touching the module files' own mode and SELinux label.
- Zygisk and Zygisk Next modules are served side by side: a module may ship both a `zygisk/<arch>.so` and a `zn_modules.txt` (LSPosed does), and each is handled by its own path without excluding the other.

## Dependencies

| Tool            | Description                            |
|-----------------|----------------------------------------|
| `Android NDK`   | Native Development Kit for Android     |

### C/C++ Dependencies

| Dependency        | Description                                              |
|-------------------|----------------------------------------------------------|
| `PLTI`            | Simple PLT Hook for Android, used by the injector itself |
| `LSPlt`           | PLT hooking library for Android, serves the ZN `pltHook` API |
| `Dobby`           | In-process inline hooking engine, serves the ZN `inlineHook` API |
| `CSOLoader`       | Custom ELF loader, maps standard Zygisk modules          |
| `xz-embedded`     | XZ decompression for ELF `.gnu_debugdata`                |

## Installation

### 1. Select the right zip

Two things decide which archive you need:

**Root solution** — pick the flavour matching your root manager (`VexZygisk` for KernelSU, `VexZygisk-APatch` for APatch). The installer checks the manager you are flashing from and aborts otherwise, so a mismatch cannot brick anything — it simply refuses to install.

**Build type** — `release` should be the one chosen for most cases, it removes app-level logging and offers more optimized binaries. `debug` offers the opposite, with heavy logging and no optimizations. For this reason, **you should only use it for debugging purposes** and **when obtaining logs for creating an Issue**.

As for branches, you should always use the `main` branch, unless told otherwise by the developers, or if you want to test upcoming features and are aware of the risks involved.

### 2. Flash the zip

Flash it from the matching root manager: go to the `Modules` section of the KernelSU or APatch app and select the zip you downloaded.

After flashing, check the installation logs to ensure there are no errors, and if everything is fine, you can reboot your device.

### 3. Verify the installation

After rebooting, you can verify if VexZygisk is working properly by checking the module description in the `Modules` section of your root manager. The description should indicate that the necessary daemons are running, and it should look similar to this: `[Monitor: ✅, VexZygisk 64-bit: ✅] Standalone implementation of Zygisk.`

You can also ask the tracer directly, from a root shell:

```sh
/data/adb/modules/rezygisk/bin/zygisk-ptrace64 info
```

which prints the daemon PID, the root solution in use, and the loaded modules.

> [!NOTE]
> VexZygisk builds and injects arm64 only. On a 64-bit device the secondary 32-bit Zygote is left untouched - it is rarely used and injecting it brings no benefit - and 32-bit only devices are no longer supported.

## Building

The whole project builds with plain `make` (plus the NDK pointed at by `NDK_PATH`):

```sh
make all                       # KernelSU flavour: debug + release
make apatch                    # APatch flavour: release, into build-apatch/
make ROOT_IMPL=apatch release  # explicit form
```

- `ROOT_IMPL` selects the backend (`ksu`, the default, or `apatch`); both flavours build from the same sources and land in separate trees so their caches never mix.
- A CI run on `main` produces both release archives plus a generated `update.json`, and runs the host-side suite (`tests/host/`) before anything is published: the ELF reader and its mini-debug decompressor, the mountinfo parsing behind the revert, the APatch package configuration parser, and what counts as a module trace — the parts that are plain text on a build host and silent failures on a device.

## Support

If something is not working, open an [Issue](https://github.com/Lxiaoyao077/VexZygisk/issues) with a log from the `debug` build attached.

## Contribution

Pull requests are welcome. Keep the existing code style and test your changes with a `debug` build before submitting.

## Credits & Acknowledgements

This repository stands on other projects' work; the credits below map the
pieces to their sources.

* [ReZygisk](https://github.com/PerformanC/ReZygisk): The base project this repository forks and rewrites in C
* [NyaZygisk](https://github.com/HSSkyBoy/NyaZygisk): The HyperOS Runtime support (hyos_spawner interception, the runtime table, the fork and SELinux hooks that deliver `onAppSpecialized`) and the Zygisk Next fixes ported from here — symbol lookup confined to the library's own tables, `pltHook` backup semantics, the monitor's spawner handling and the upgrade-time `module.prop` guard
* [ZygiskNext](https://github.com/Dr-TSNG/ZygiskNext): The original Zygisk Next module architecture and the API VexZygisk speaks
* [ZygiskNextNext](https://github.com/VeryBaaad/ZygiskNextNext): Reference implementation for the standalone Zygisk Next API
* [Magisk](https://github.com/topjohnwu/Magisk): The foundation of modern Android root and Zygisk itself
* [OnyxZygisk](https://github.com/OnyxZygisk/OnyxZygisk): The revert-only mount model — the trace selection and the in-place revert a hidden process runs on its own copy of the mount tree
* [KernelSU](https://github.com/tiann/KernelSU): The kernel interface the KernelSU flavour talks to
* [APatch](https://github.com/bmax121/APatch): The kernel patch that the APatch flavour manages alongside
* [Dobby](https://github.com/LSPosed/Dobby): In-process code hooking engine behind the ZN `inlineHook` API
* [LSPlt](https://github.com/LSPosed/LSPlt): PLT hooking library behind the ZN `pltHook` API
* [PLTI](https://github.com/PerformanC/PLTI): PLT hooking used by the injector itself
* [CSOLoader](https://github.com/ThePedroo/CSOLoader): The custom ELF loader that maps standard Zygisk modules
* [xz-embedded](https://tukaani.org/xz/embedded.html): Public-domain XZ decompressor for `.gnu_debugdata`

## License

VexZygisk is licensed under [AGPL 3.0](./LICENSE). You can read more about it on [Open Source Initiative](https://opensource.org/licenses/AGPL-3.0).
