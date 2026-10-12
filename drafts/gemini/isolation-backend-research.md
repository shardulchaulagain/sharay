# macOS Isolation Backend Research: Achieving Memory, Egress, and Fork Containment

**Author**: Gemini (Principal Architect)  
**Date**: October 12, 2026  
**Context**: macOS on Apple Silicon (macOS 26.6), unprivileged execution, zero Docker/Podman dependencies.  
**Requirement**: Enforce memory caps, per-destination egress allowlists, and fork containment before third-party scanner tools can execute.

---

## 1. Candidate Isolation Technologies on Darwin

| Backend Technology | Requires Root? | Memory Cap | Hard Disk Quota | Live Egress Allowlist | Fork Containment | Startup Overhead | Feasibility on This Host |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **launchd / posix_spawn limits** | No | No (ignored by kernel) | No | No | Partial (tracked job) | ~50 ms | High, but leaves all 3 missing gaps open. |
| **APFS RAM Disk / Sparse Image** | **No** | No | **Yes (strict ENOSPC)** | No | N/A | **~150 ms (estimated)** | **Immediately usable** without root for disk quotas. |
| **pf (Packet Filter)** | **Yes** | No | No | **Yes (kernel table)** | N/A | ~10 ms | Blocked by root requirement. |
| **Seatbelt Enhanced (sandbox-exec)** | No | No | No (without image) | Partial (literal IPs) | No (fork escapes SIGKILL) | ~20 ms | Currently active in `services/scanner_worker`. |
| **macOS Virtualization.framework** | **No** | **Yes (strict VM RAM)** | **Yes (fixed virtio disk)** | **Yes (internal nftables/virtio-net)** | **Yes (Linux cgroups inside VM)** | **~350–500 ms (unverified)** | **Best architectural solution** without root. |

---

## 2. Detailed Technical Breakdown & Sources

### A. APFS RAM Disk for Hard Disk Quotas (Immediate Unprivileged Addition)
- **Source**: Apple `hdiutil(1)` manpage and APFS developer documentation.
- **Mechanism**: Use `hdiutil attach -nomount ram://<sectors>` to allocate an in-memory block device, format as APFS (`newfs_apfs`), and mount as the tool's private scratch directory.
- **Root Requirement**: None. Unprivileged macOS console users can attach and mount ramdisks.
- **Enforcement**: Any process (even malicious or runaway child) writing past the allocated volume receives `ENOSPC` directly from the kernel VFS layer.
- **Teardown**: `hdiutil detach <dev>` automatically wipes all data from memory upon process exit.
- **Proof-of-Concept Command Sequence (Not yet run; pending human approval)**:
  ```bash
  # Allocate a 50 MiB RAM disk (50 * 2048 = 102400 sectors of 512 bytes)
  DEV=$(hdiutil attach -nomount ram://102400 | tr -d '[:space:]')
  # Initialize APFS filesystem without root
  newfs_apfs -v "SCRATCH_QUOTA" "$DEV"
  # Mount to private scratch location
  mkdir -p /tmp/sharay_scratch_poc
  mount_apfs "$DEV" /tmp/sharay_scratch_poc
  # Verification: writing 60 MiB to the 50 MiB volume must fail with ENOSPC
  dd if=/dev/zero of=/tmp/sharay_scratch_poc/overflow.bin bs=1M count=60
  # Expected result: dd fails with 'dd: /tmp/sharay_scratch_poc/overflow.bin: No space left on device' (exit code 1)
  # Cleanup
  umount /tmp/sharay_scratch_poc
  hdiutil detach "$DEV"
  rmdir /tmp/sharay_scratch_poc
  ```

### B. Apple Virtualization.framework (Unprivileged MicroVM)
- **Official Documentation Sources**:
  - Main Framework: `https://developer.apple.com/documentation/virtualization`
  - VM Lifecycle: `https://developer.apple.com/documentation/virtualization/vzvirtualmachine`
  - Hardware Configuration: `https://developer.apple.com/documentation/virtualization/vzvirtualmachineconfiguration`
  - Network NAT Attachment: `https://developer.apple.com/documentation/virtualization/vznatnetworkdeviceattachment`
  - Socket / File Handle Network Attachment: `https://developer.apple.com/documentation/virtualization/vzfilehandlenetworkdeviceattachment`
- **Memory Enforcement**:
  `VZVirtualMachineConfiguration.memorySize` allocates an exact memory footprint (e.g., 512 MB). The hypervisor enforces a strict hardware boundary; an OOM event inside the VM kills the offending task via the Linux kernel OOM killer, completely insulating the host Mac.
- **Fork Containment**:
  The VM runs a minimal Linux kernel + initramfs. Inside the VM, cgroups v2 manages processes. A child calling `setsid()` remains trapped inside the microVM's pid namespace and hypervisor sandbox.
- **Egress Allowlist (virtio-net socket filters)**:
  `VZFileHandleNetworkDeviceAttachment` allows attaching a UNIX domain socket or pair of file descriptors directly to the VM's virtio-net interface. Traffic routed through this interface can be inspected and filtered in user-space by the parent process, permitting connections only to approved host/port destinations.
  *Note on performance*: The startup boot time figure (~350–500 ms) is an **unverified assumption based on published microVM industry benchmarks** (e.g. Firecracker/Virtualization.framework Alpine boot times), not a measurement performed on this Mac.

---

## 3. Recommended Phased Implementation

1. **Phase 1 (Immediate Scratch Quota)**:
   Integrate the `hdiutil ram://` ephemeral disk into `services/scanner_worker/__init__.py` when `allow_scratch_writes=True`.
2. **Phase 2 (Long-term Live Gate Backend)**:
   Implement `services/scanner_worker/microvm_runner.py` backed by `Virtualization.framework` and a bundled minimal kernel.
