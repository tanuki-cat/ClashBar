import Darwin
import Foundation

/// Read-only view of the network topology used to decide what the tunnel must leave alone.
enum CoexistenceDiscovery {
    private static let peerInterfacePrefixes = ["utun", "ipsec", "feth", "tun"]
    private static let physicalInterfacePrefixes = ["en", "bridge", "ppp", "pdp"]
    private static let ignoredInterfacePrefixes = ["lo", "awdl", "llw", "gif", "stf", "anpi"]

    struct CommandOutput: Sendable {
        let text: String
        let exitCode: Int32
    }

    typealias CommandRunner = @Sendable (String, [String]) -> CommandOutput?

    static func snapshot(runner: CommandRunner = Self.runCommand) -> CoexistenceSnapshot {
        var snapshot = CoexistenceSnapshot()
        let interfaces = self.readInterfaces()
        snapshot.interfaces = interfaces.compactMap { entry in
            guard entry.kind == .peer else { return nil }
            return DetectedInterface(
                name: entry.name,
                family: entry.family,
                address: entry.address,
                prefixLength: entry.prefixLength,
                routedSubnets: [entry.cidr])
        }
        snapshot.physicalSubnets = interfaces
            .filter { $0.kind == .physical && $0.family == .v4 && $0.prefixLength < 32 }
            .map { $0.cidr }
        if let output = runner("/usr/bin/systemextensionsctl", ["list"]) {
            snapshot.extensions = self.parseExtensions(output.text)
        }
        if let output = runner("/usr/sbin/scutil", ["--dns"]) {
            snapshot.resolvers = self.parseResolvers(output.text)
        }
        return snapshot
    }

    // MARK: - Interfaces

    private struct InterfaceEntry {
        enum Kind { case peer, physical, ignored }
        let name: String
        let family: DetectedInterface.Family
        let address: String
        let prefixLength: Int
        let kind: Kind
        var cidr: String { self.address + "/" + String(self.prefixLength) }
    }

    private static func readInterfaces() -> [InterfaceEntry] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let head else { return [] }
        defer { freeifaddrs(head) }

        var result: [InterfaceEntry] = []
        for pointer in sequence(first: head, next: { $0.pointee.ifa_next }) {
            let interface = pointer.pointee
            guard let sockaddr = interface.ifa_addr else { continue }
            let family: DetectedInterface.Family
            switch Int32(sockaddr.pointee.sa_family) {
            case AF_INET: family = .v4
            case AF_INET6: family = .v6
            default: continue
            }
            let name = String(cString: interface.ifa_name)
            let kind = self.classify(name)
            guard kind != .ignored else { continue }
            guard let address = self.addressString(sockaddr, family: family) else { continue }
            let prefix = self.prefixLength(interface.ifa_netmask, family: family)
            result.append(InterfaceEntry(
                name: name, family: family, address: address, prefixLength: prefix, kind: kind))
        }
        return result
    }

    private static func classify(_ name: String) -> InterfaceEntry.Kind {
        let lowered = name.lowercased()
        if self.ignoredInterfacePrefixes.contains(where: { lowered.hasPrefix($0) }) { return .ignored }
        if self.peerInterfacePrefixes.contains(where: { lowered.hasPrefix($0) }) { return .peer }
        if self.physicalInterfacePrefixes.contains(where: { lowered.hasPrefix($0) }) { return .physical }
        return .ignored
    }

    private static func addressString(
        _ sockaddr: UnsafeMutablePointer<sockaddr>, family: DetectedInterface.Family) -> String?
    {
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let result = getnameinfo(
            sockaddr,
            socklen_t(sockaddr.pointee.sa_len),
            &host,
            socklen_t(host.count),
            nil,
            0,
            NI_NUMERICHOST)
        guard result == 0 else { return nil }
        let bytes = host.prefix { $0 != 0 }.map(UInt8.init(bitPattern:))
        guard let text = String(bytes: bytes, encoding: .utf8), !text.isEmpty else { return nil }
        // Link-local IPv6 addresses carry a scope suffix that is not part of the address.
        return family == .v6 ? String(text.split(separator: "%").first ?? Substring(text)) : text
    }

    private static func prefixLength(
        _ netmask: UnsafeMutablePointer<sockaddr>?, family: DetectedInterface.Family) -> Int
    {
        let fallback = family == .v4 ? 32 : 128
        guard let netmask, Int32(netmask.pointee.sa_family) == (family == .v4 ? AF_INET : AF_INET6) else {
            return fallback
        }
        return withUnsafePointer(to: netmask.pointee) { pointer in
            pointer.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { address in
                var value = address.pointee.sin_addr.s_addr.bigEndian
                var bits = 0
                while value & 0x8000_0000 != 0 {
                    bits += 1
                    value <<= 1
                }
                return bits
            }
        }
    }

    // MARK: - Parsers

    static func parseExtensions(_ output: String) -> [DetectedExtension] {
        output.split(separator: "\n").compactMap { line -> DetectedExtension? in
            let fields = line.split(whereSeparator: { $0 == "\t" }).map(String.init)
            guard let bundleField = fields.first(where: { $0.contains(".network-extension") }) else {
                return nil
            }
            let bundleIdentifier = bundleField
                .split(separator: " ")
                .first
                .map(String.init) ?? bundleField
            guard bundleIdentifier.contains(".") else { return nil }
            let displayName = fields.last(where: { $0.contains("[") == false && $0 != bundleField }) ?? ""
            return DetectedExtension(
                bundleIdentifier: bundleIdentifier,
                displayName: displayName.trimmingCharacters(in: .whitespaces),
                isActive: line.contains("[activated enabled]"))
        }
    }

    static func parseResolvers(_ output: String) -> [ScopedResolver] {
        var result: [ScopedResolver] = []
        var nameservers: [String] = []
        var domains: [String] = []
        var interfaceName: String?

        func flush() {
            guard !nameservers.isEmpty else {
                nameservers = []
                domains = []
                interfaceName = nil
                return
            }
            result.append(ScopedResolver(
                interfaceName: interfaceName,
                nameservers: nameservers,
                searchDomains: domains))
            nameservers = []
            domains = []
            interfaceName = nil
        }

        for rawLine in output.split(separator: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("resolver #") {
                flush()
                continue
            }
            let parts = line.split(separator: ":", maxSplits: 1).map {
                $0.trimmingCharacters(in: .whitespaces)
            }
            guard parts.count == 2 else { continue }
            let key = parts[0]
            let value = parts[1]
            if key.hasPrefix("nameserver[") || key == "nameserver" {
                nameservers.append(value)
            } else if key.hasPrefix("search domain[") || key == "domain" {
                let domain = value.hasSuffix("*") ? "" : value
                if !domain.isEmpty { domains.append(domain) }
            } else if key == "if_index" {
                // Format: 24 (utun4)
                if let open = value.firstIndex(of: "("), let close = value.lastIndex(of: ")"),
                   open < close
                {
                    interfaceName = String(value[value.index(after: open)..<close])
                }
            }
        }
        flush()
        return result
    }

    // MARK: - Commands

    private static func runCommand(_ executable: String, _ arguments: [String]) -> CommandOutput? {
        guard FileManager.default.isExecutableFile(atPath: executable) else { return nil }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        let finished = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in finished.signal() }
        do {
            try process.run()
        } catch {
            return nil
        }
        guard finished.wait(timeout: .now() + 3) == .success else {
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            _ = finished.wait(timeout: .now() + 1)
            return nil
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return CommandOutput(
            text: String(data: data, encoding: .utf8) ?? "",
            exitCode: process.terminationStatus)
    }
}
