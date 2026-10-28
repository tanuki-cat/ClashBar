import Darwin
import Foundation

struct SystemDNSCacheFlusher {
    struct Command: Equatable {
        let executable: String
        let arguments: [String]
    }

    static let commands = [
        Command(executable: "/usr/bin/dscacheutil", arguments: ["-flushcache"]),
        Command(executable: "/usr/bin/killall", arguments: ["-HUP", "mDNSResponder"]),
    ]

    static func flush(run: (Command) throws -> Void = Self.runCommand) throws {
        for command in self.commands {
            try run(command)
        }
    }

    private static func runCommand(_ command: Command) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: command.executable)
        process.arguments = command.arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        let finished = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in finished.signal() }
        try process.run()
        // Keep both commands within the client's four-second XPC response budget.
        guard finished.wait(timeout: .now() + 1.5) == .success else {
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            throw NSError(domain: "ClashBar.DNSCache", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "DNS cache command timed out: \(command.executable)",
            ])
        }
        guard process.terminationStatus == 0 else {
            throw NSError(domain: "ClashBar.DNSCache", code: Int(process.terminationStatus), userInfo: [
                NSLocalizedDescriptionKey: "DNS cache command failed: \(command.executable) (\(process.terminationStatus))",
            ])
        }
    }
}
