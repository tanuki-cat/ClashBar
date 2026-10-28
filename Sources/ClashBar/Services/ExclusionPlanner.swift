import Foundation

// MARK: - Discovery snapshot

struct DetectedInterface: Equatable, Sendable {
    enum Family: String, Equatable, Sendable {
        case v4
        case v6
    }

    let name: String
    let family: Family
    let address: String
    let prefixLength: Int
    /// Subnets this interface actually carries, read from the routing table.
    let routedSubnets: [String]

    var cidr: String { self.address + "/" + String(self.prefixLength) }
}

struct DetectedExtension: Equatable, Sendable {
    let bundleIdentifier: String
    let displayName: String
    let isActive: Bool

    init(bundleIdentifier: String, displayName: String = "", isActive: Bool = true) {
        self.bundleIdentifier = bundleIdentifier
        self.displayName = displayName
        self.isActive = isActive
    }
}

struct CoexistenceSnapshot: Equatable, Sendable {
    var interfaces: [DetectedInterface] = []
    var extensions: [DetectedExtension] = []
    /// Subnets of physical interfaces; they must never be excluded from the tunnel.
    var physicalSubnets: [String] = []

    static let empty = CoexistenceSnapshot()
}

struct OwnTunInfo: Equatable, Sendable {
    let deviceName: String
    let subnets: [String]

    init(deviceName: String, subnets: [String] = []) {
        self.deviceName = deviceName
        self.subnets = subnets
    }
}

// MARK: - Plan

struct ExclusionPlan: Equatable, Sendable {
    var routeExclusions: [String] = []
    /// Domains that must resolve to a real address instead of a fake one.
    var realDomains: [String] = []
    var hostPins: [String: String] = [:]
    var directRules: [String] = []
    var nameserverPolicy: [String: [String]] = [:]
    var sniffingSkips: [String] = []

    var isEmpty: Bool {
        self.routeExclusions.isEmpty && self.realDomains.isEmpty && self.hostPins.isEmpty
            && self.directRules.isEmpty && self.nameserverPolicy.isEmpty && self.sniffingSkips.isEmpty
    }
}

// MARK: - CIDR

struct CidrBlock: Equatable, Sendable {
    enum Family: Equatable, Sendable {
        case v4
        case v6
    }

    let family: Family
    let prefixLength: Int
    let raw: String
    /// Network address as a host-order integer; only meaningful for IPv4.
    let network: UInt32

    init?(_ text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        let parts = trimmed.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count <= 2, parts.isEmpty == false else { return nil }
        let addressText = String(parts[0])
        let isV4 = addressText.contains(":") == false
        let family: Family = isV4 ? .v4 : .v6
        let maxPrefix = isV4 ? 32 : 128
        let prefix: Int
        if parts.count == 2 {
            guard let parsed = Int(parts[1]), (0...maxPrefix).contains(parsed) else { return nil }
            prefix = parsed
        } else {
            prefix = maxPrefix
        }
        guard let network = Self.parse(address: addressText, family: family) else { return nil }
        self.family = family
        self.prefixLength = prefix
        self.raw = addressText + "/" + String(prefix)
        self.network = network
    }

    var isIPv4: Bool { self.family == .v4 }

    private static func parse(address: String, family: Family) -> UInt32? {
        switch family {
        case .v4:
            let octets = address.split(separator: ".", omittingEmptySubsequences: false)
            guard octets.count == 4 else { return nil }
            var value: UInt32 = 0
            for octet in octets {
                guard let byte = UInt8(octet) else { return nil }
                value = (value << 8) | UInt32(byte)
            }
            return value
        case .v6:
            // Full IPv6 arithmetic is unnecessary here: only syntax gets validated.
            let groups = address.split(separator: ":", omittingEmptySubsequences: false)
            guard address.contains(":"), (3...8).contains(groups.count) else { return nil }
            for group in groups where group.isEmpty == false {
                guard UInt16(group, radix: 16) != nil else { return nil }
            }
            return 0
        }
    }

    private func masked(_ bits: Int) -> UInt32 {
        guard bits > 0 else { return 0 }
        return self.network & (~UInt32(0) << (32 - bits))
    }

    /// True when this block fully contains another one.
    func contains(_ other: CidrBlock) -> Bool {
        guard self.family == other.family, self.isIPv4, other.isIPv4 else { return false }
        guard self.prefixLength <= other.prefixLength else { return false }
        return self.masked(self.prefixLength) == other.masked(self.prefixLength)
    }
}

// MARK: - Planner

enum ExclusionPlanner {
    static let maxEntriesPerCategory = 64

    /// Reserved or unroutable ranges that are never worth excluding explicitly.
    private static let forbiddenV4 = [
        "127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32", "169.254.0.0/16",
    ]

    static func plan(
        snapshot: CoexistenceSnapshot,
        catalog: [LocalEndpointRule],
        own: OwnTunInfo?) -> ExclusionPlan
    {
        var plan = ExclusionPlan()
        let active = catalog.filter { self.isActive($0, snapshot: snapshot) }

        var routeBlocks: [CidrBlock] = []
        for rule in active {
            for address in rule.addresses {
                guard let block = CidrBlock(address), self.isAcceptable(block, snapshot: snapshot, own: own) else {
                    continue
                }
                routeBlocks.append(block)
                let keyword = block.isIPv4 ? "IP-CIDR" : "IP-CIDR6"
                plan.directRules.append(keyword + "," + block.raw + ",DIRECT,no-resolve")
            }
            for domain in rule.domains {
                plan.realDomains.append(domain)
                plan.directRules.append("DOMAIN," + domain + ",DIRECT")
            }
            for (domain, address) in rule.pinnedHosts.sorted(by: { $0.key < $1.key }) {
                plan.hostPins[domain] = address
            }
            plan.sniffingSkips.append(contentsOf: rule.domains)
        }

        // Dynamic part: subnets actually carried by other tunnel interfaces.
        for interface in snapshot.interfaces where self.isPeerInterface(interface, own: own) {
            for subnet in interface.routedSubnets {
                guard let block = CidrBlock(subnet), self.isAcceptable(block, snapshot: snapshot, own: own) else {
                    continue
                }
                routeBlocks.append(block)
            }
        }

        plan.routeExclusions = self.deduplicated(routeBlocks.map { $0.raw })
        plan.directRules = self.deduplicated(plan.directRules)
        plan.realDomains = self.deduplicated(plan.realDomains)
        plan.sniffingSkips = self.deduplicated(plan.sniffingSkips)
        return plan
    }

    static func isActive(_ rule: LocalEndpointRule, snapshot: CoexistenceSnapshot) -> Bool {
        switch rule.activation {
        case .always:
            return true
        case let .whenInterfacePresent(prefix):
            return snapshot.interfaces.contains {
                $0.name.lowercased().hasPrefix(prefix.lowercased())
            }
        case let .whenExtensionPresent(bundleIdentifier):
            return snapshot.extensions.contains {
                $0.isActive && $0.bundleIdentifier.caseInsensitiveCompare(bundleIdentifier) == .orderedSame
            }
        }
    }

    private static func isPeerInterface(_ interface: DetectedInterface, own: OwnTunInfo?) -> Bool {
        let name = interface.name.lowercased()
        if let own, name == own.deviceName.lowercased() { return false }
        return name.hasPrefix("utun") || name.hasPrefix("ipsec")
            || name.hasPrefix("feth") || name.hasPrefix("tun")
    }

    private static func isAcceptable(
        _ block: CidrBlock,
        snapshot: CoexistenceSnapshot,
        own: OwnTunInfo?) -> Bool
    {
        // Never exclude the entire address space.
        guard block.prefixLength > 0 else { return false }
        guard block.isIPv4 else {
            return block.raw != "::/0" && !block.raw.hasPrefix("fe80:")
        }
        for forbidden in self.forbiddenV4 {
            guard let range = CidrBlock(forbidden) else { continue }
            if range.contains(block) { return false }
        }
        // Never swallow a physical interface subnet.
        for subnet in snapshot.physicalSubnets {
            guard let physical = CidrBlock(subnet), physical.isIPv4 else { continue }
            if block.contains(physical) { return false }
        }
        // Excluding our own tunnel subnet is pointless.
        if let own {
            for subnet in own.subnets {
                guard let ownBlock = CidrBlock(subnet), ownBlock.isIPv4 else { continue }
                if block.contains(ownBlock) || ownBlock.contains(block) { return false }
            }
        }
        return true
    }

    private static func deduplicated(_ values: [String]) -> [String] {
        var seen: Set<String> = []
        var result: [String] = []
        for value in values where seen.insert(value).inserted {
            result.append(value)
            if result.count >= self.maxEntriesPerCategory { break }
        }
        return result
    }
}
