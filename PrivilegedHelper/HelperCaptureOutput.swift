import Foundation

// MARK: - HelperCaptureOutput
//
// Owns the on-disk location for pcap output. The helper runs as root, so any
// caller-controlled path could be redirected via symlink or TOCTOU into a
// privileged write primitive. This type:
//
//   • Forces output into a single helper-owned directory.
//   • Sanitizes the caller-suggested filename (basename only, safe charset).
//   • Pre-creates the file with O_CREAT|O_EXCL|O_NOFOLLOW + 0o600 so tcpdump
//     opens an inode we already control.
//   • Resolves the realpath and verifies it still lives inside the helper
//     directory after creation (defense in depth against TOCTOU).
//
// Failure behavior: fail closed — any error returns nil and the caller
// reports capture failure.
//
// Tradeoff on permissions:
//   tcpdump writes the pcap as root. The user-level scanners (tshark, zeek,
//   ngrep) need to read it. We finalise the file at 0o640 with group=admin so
//   admin users can read it, but it is no longer world-readable as before.
//   A stricter design would have the helper return the bytes directly; that
//   is a larger refactor and is deferred.

enum HelperCaptureOutput {

    /// Helper-owned directory for pcap output. Root-owned, 0o755 so user-level
    /// scanners can traverse it; the files inside are 0o640 (root:admin).
    static let directory = "/var/db/com.woady.phantom.helper/captures"

    /// File mode applied after tcpdump finishes writing.
    /// Owner (root) read/write, group (admin) read, others none.
    static let finalMode: mode_t = 0o640

    /// Group used for the finalised pcap. `admin` (gid 80 on macOS) is the
    /// group that includes administrator users by default, which matches the
    /// user that installed the helper via SMJobBless.
    static let finalGroupName = "admin"

    /// Prepares a writable output path. Returns nil on any error.
    /// The returned path is guaranteed to live inside `directory`, contain
    /// no symlinks, and exist as a freshly created regular file owned by the
    /// helper with mode 0o600 (further relaxed to `finalMode` after capture).
    static func prepare(suggestedName: String) -> String? {
        guard ensureDirectory() else { return nil }

        let safeName = sanitize(filename: suggestedName)
        let target = (directory as NSString).appendingPathComponent(safeName)

        // Remove any stale entry (older pcap from a previous run). We only
        // unlink regular files inside our own directory — if anything else
        // squats the path, bail out rather than touching it.
        if let attrs = try? FileManager.default.attributesOfItem(atPath: target),
           let type = attrs[.type] as? FileAttributeType {
            guard type == .typeRegular else { return nil }
            try? FileManager.default.removeItem(atPath: target)
        }

        // O_CREAT | O_EXCL | O_NOFOLLOW: refuse to follow a symlink, refuse
        // to reuse an existing inode. If anything raced us, open() returns -1.
        let fd = target.withCString { cstr in
            open(cstr, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0o600)
        }
        guard fd >= 0 else { return nil }
        close(fd)

        // Verify the realpath still resolves inside our directory. Guards
        // against the dir itself being a symlink swapped between create
        // and use.
        guard let real = realpath(of: target),
              real.hasPrefix(canonicalDirectory() + "/")
        else {
            try? FileManager.default.removeItem(atPath: target)
            return nil
        }

        return real
    }

    /// Apply final permissions and group after tcpdump has finished writing.
    /// Best effort — failure to chown/chmod does not invalidate the pcap.
    static func finalize(path: String) {
        let gid = adminGID()
        _ = path.withCString { chown($0, 0, gid) }
        _ = path.withCString { chmod($0, finalMode) }
    }

    // MARK: - Internals

    private static func ensureDirectory() -> Bool {
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: directory, isDirectory: &isDir) {
            return isDir.boolValue
        }
        do {
            try FileManager.default.createDirectory(
                atPath: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o755]
            )
            return true
        } catch {
            return false
        }
    }

    /// Restrict filenames to a conservative charset and strip any path
    /// separators or dotfiles. Returns a safe default if the input is empty
    /// or entirely stripped.
    static func sanitize(filename: String) -> String {
        let base = (filename as NSString).lastPathComponent
        let allowed = CharacterSet(charactersIn:
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")
        let scrubbed = String(base.unicodeScalars.filter { allowed.contains($0) })
        let trimmed = scrubbed.drop(while: { $0 == "." })   // no dotfiles
        if trimmed.isEmpty { return "phantom-capture.pcap" }
        return String(trimmed)
    }

    private static func canonicalDirectory() -> String {
        realpath(of: directory) ?? directory
    }

    private static func realpath(of path: String) -> String? {
        var buf = [CChar](repeating: 0, count: Int(PATH_MAX))
        guard path.withCString({ Darwin.realpath($0, &buf) }) != nil else { return nil }
        return String(cString: buf)
    }

    private static func adminGID() -> gid_t {
        var result: UnsafeMutablePointer<group>?
        var storage = group()
        var buf = [CChar](repeating: 0, count: 1024)
        let rc = getgrnam_r(finalGroupName, &storage, &buf, buf.count, &result)
        if rc == 0, result != nil { return storage.gr_gid }
        return 80   // macOS default admin gid
    }
}
