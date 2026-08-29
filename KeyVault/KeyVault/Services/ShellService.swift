import Foundation

/// Runs a system tool and collects what it wrote.
///
/// Both output pipes are drained on their own queues *while* the child runs,
/// rather than read from `terminationHandler` once it has exited. Reading
/// after exit deadlocks, and not rarely: a macOS pipe holds 64 KB, so a child
/// that fills stdout blocks waiting for a reader that will not run until the
/// child it is blocking has terminated. Neither side moves again. An export of
/// ~30 notes was enough to reach that, and the symptom was the worst kind —
/// the backup never finished and never reported a failure either.
///
/// stdin is written on a queue of its own for the same reason: a payload
/// larger than the pipe buffer cannot be handed over in one blocking write
/// while the child is itself blocked writing output nobody is reading.
actor ShellService {
    /// Accumulates the child's output. A reference type with its own lock, so
    /// the reader queues can fill it concurrently without a data race.
    private final class Output: @unchecked Sendable {
        private let lock = NSLock()
        private var out = Data()
        private var err = Data()

        func appendOut(_ data: Data) { lock.lock(); out += data; lock.unlock() }
        func appendErr(_ data: Data) { lock.lock(); err += data; lock.unlock() }

        var strings: (stdout: String, stderr: String) {
            lock.lock()
            defer { lock.unlock() }
            return (String(data: out, encoding: .utf8) ?? "",
                    String(data: err, encoding: .utf8) ?? "")
        }
    }

    /// Writing to a pipe whose reader has already exited raises SIGPIPE, and
    /// the default disposition for SIGPIPE is to kill the process — so a tool
    /// that quits early, gpg on a passphrase it will not accept for instance,
    /// took the whole app down while stdin was still being handed over.
    /// Ignoring it turns that into a plain EPIPE the write below discards.
    /// Evaluated once, on first use, before any child exists.
    private static let ignoreSIGPIPE: Void = {
        signal(SIGPIPE, SIG_IGN)
    }()

    func run(
        _ executable: String,
        arguments: [String]
    ) async throws -> (stdout: String, stderr: String, status: Int32) {
        try await execute(executable, arguments: arguments, stdinData: nil)
    }

    func runWithStdin(
        _ executable: String,
        arguments: [String],
        stdinData: Data
    ) async throws -> (stdout: String, stderr: String, status: Int32) {
        try await execute(executable, arguments: arguments, stdinData: stdinData)
    }

    private func execute(
        _ executable: String,
        arguments: [String],
        stdinData: Data?
    ) async throws -> (stdout: String, stderr: String, status: Int32) {
        _ = Self.ignoreSIGPIPE

        guard FileManager.default.fileExists(atPath: executable) else {
            throw KeyError.toolNotFound(executable)
        }

        return try await withCheckedThrowingContinuation { continuation in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: executable)
            process.arguments = arguments

            let stdoutPipe = Pipe()
            let stderrPipe = Pipe()
            process.standardOutput = stdoutPipe
            process.standardError = stderrPipe

            let stdinPipe: Pipe? = stdinData == nil ? nil : Pipe()
            if let stdinPipe { process.standardInput = stdinPipe }

            let io = DispatchQueue(
                label: "io.github.sevmorris.KeyVault.shell",
                attributes: .concurrent
            )
            let group = DispatchGroup()
            let output = Output()

            group.enter()
            io.async {
                output.appendOut(stdoutPipe.fileHandleForReading.readDataToEndOfFile())
                group.leave()
            }
            group.enter()
            io.async {
                output.appendErr(stderrPipe.fileHandleForReading.readDataToEndOfFile())
                group.leave()
            }

            // Resume only once both readers have seen EOF, so nothing the tool
            // wrote is dropped just because it exited promptly after writing.
            process.terminationHandler = { proc in
                let status = proc.terminationStatus
                group.notify(queue: io) {
                    let (out, err) = output.strings
                    continuation.resume(returning: (stdout: out, stderr: err, status: status))
                }
            }

            do {
                try process.run()
                if let stdinPipe, let stdinData {
                    group.enter()
                    io.async {
                        let handle = stdinPipe.fileHandleForWriting
                        // The throwing form on purpose: the older write(_:)
                        // raises an Objective-C exception on a broken pipe,
                        // which Swift cannot catch, so a tool exiting early
                        // (a wrong passphrase, say) took the app down with it.
                        try? handle.write(contentsOf: stdinData)
                        try? handle.close()
                        group.leave()
                    }
                }
            } catch {
                // The child never started, so nothing will ever close these.
                // Close them here or the readers block for the life of the app.
                try? stdoutPipe.fileHandleForWriting.close()
                try? stderrPipe.fileHandleForWriting.close()
                continuation.resume(throwing: error)
            }
        }
    }
}
