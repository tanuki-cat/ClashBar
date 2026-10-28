import Foundation
import Yams

/// Applies an exclusions plan to a runtime-only copy of the user configuration.
enum RuntimeOverlay {
    enum ConfigError: LocalizedError {
        case invalidYAML
        case invalidField(String)

        var errorDescription: String? {
            switch self {
            case .invalidYAML:
                return "Unable to parse YAML for the runtime overlay."
            case let .invalidField(field):
                return "Unsupported configuration field for the runtime overlay: " + field
            }
        }
    }

    static func apply(source: String, plan: ExclusionPlan) throws -> String {
        let parsed: Node
        do {
            guard let node = try Yams.compose(yaml: source) else { throw ConfigError.invalidYAML }
            parsed = node
        } catch {
            // Parser errors can echo credential-bearing source lines back to the caller.
            throw ConfigError.invalidYAML
        }
        var normalizer = try YAMLNormalizer(root: parsed)
        var root = try normalizer.expand(parsed)
        guard root.mapping != nil else { throw ConfigError.invalidYAML }

        if plan.isEmpty == false {
            root = try self.applyDNS(plan: plan, root: root)
            root = self.applyHosts(plan: plan, root: root)
            root = self.applyTun(plan: plan, root: root)
            root = try self.applyRules(plan: plan, root: root)
            root = try self.applySniffer(plan: plan, root: root)
        }
        return try Yams.serialize(node: root, allowUnicode: true)
    }

    // MARK: - Sections

    private static func applyDNS(plan: ExclusionPlan, root: Node) throws -> Node {
        var root = root
        var dns = try self.mapping(root["dns"], field: "dns")
        if plan.realDomains.isEmpty == false || plan.realSuffixes.isEmpty == false {
            let filter = try self.strings(dns["fake-ip-filter"], field: "dns.fake-ip-filter")
            let mode = dns["fake-ip-filter-mode"]?.string?.lowercased() ?? "blacklist"
            let patternEntries = plan.realDomains + plan.realSuffixes.map { "*." + $0 }
            let ruleEntries = plan.realDomains.map { "DOMAIN," + $0 + ",real-ip" }
                + plan.realSuffixes.map { "DOMAIN-SUFFIX," + $0 + ",real-ip" }
            switch mode {
            case "blacklist":
                dns["fake-ip-filter"] = self.sequence(self.prepending(patternEntries, to: filter))
            case "rule":
                dns["fake-ip-filter"] = self.sequence(self.prepending(ruleEntries, to: filter))
            case "whitelist":
                // Keep whitelist semantics: convert to rule mode, protect local endpoints first,
                // then replay the user whitelist patterns and close with MATCH,real-ip.
                dns["fake-ip-filter-mode"] = self.scalar("rule")
                let whitelisted = try filter.flatMap(self.whitelistRules)
                dns["fake-ip-filter"] = self.sequence(ruleEntries + whitelisted + ["MATCH,real-ip"])
            default:
                throw ConfigError.invalidField("dns.fake-ip-filter-mode")
            }
        }
        if plan.nameserverPolicy.isEmpty == false {
            var policy = try self.mappingAny(root: dns, field: "dns.nameserver-policy")
            for (domain, servers) in plan.nameserverPolicy.sorted(by: { $0.key < $1.key }) {
                // An explicit user policy always wins.
                if policy[domain] == nil { policy[domain] = self.sequence(servers) }
            }
            dns["nameserver-policy"] = .mapping(policy)
        }
        root["dns"] = .mapping(dns)
        return root
    }

    private static func applyHosts(plan: ExclusionPlan, root: Node) -> Node {
        var root = root
        guard plan.hostPins.isEmpty == false else { return root }
        var hosts = (try? self.mapping(root["hosts"], field: "hosts")) ?? Node.Mapping([])
        for (domain, address) in plan.hostPins.sorted(by: { $0.key < $1.key }) {
            hosts[Node(domain)] = self.scalar(address)
        }
        root["hosts"] = .mapping(hosts)
        return root
    }

    private static func applyTun(plan: ExclusionPlan, root: Node) -> Node {
        var root = root
        guard plan.routeExclusions.isEmpty == false else { return root }
        var tun = (try? self.mapping(root["tun"], field: "tun")) ?? Node.Mapping([])
        let existing = (try? self.strings(tun["route-exclude-address"], field: "tun.route-exclude-address")) ?? []
        tun["route-exclude-address"] = self.sequence(self.prepending(plan.routeExclusions, to: existing))
        root["tun"] = .mapping(tun)
        return root
    }

    private static func applyRules(plan: ExclusionPlan, root: Node) throws -> Node {
        var root = root
        guard plan.directRules.isEmpty == false else { return root }
        let rules = try self.strings(root["rules"], field: "rules")
        root["rules"] = self.sequence(self.prepending(plan.directRules, to: rules))
        return root
    }

    private static func applySniffer(plan: ExclusionPlan, root: Node) throws -> Node {
        var root = root
        guard plan.sniffingSkips.isEmpty == false else { return root }
        guard let snifferNode = root["sniffer"], snifferNode.null == nil else { return root }
        // "sniffer: true" is a valid shorthand; only an explicit domain list gets extended.
        guard let sniffer = snifferNode.mapping, sniffer["skip-domain"] != nil else { return root }
        var updated = sniffer
        let skipDomains = try self.strings(sniffer["skip-domain"], field: "sniffer.skip-domain")
        updated["skip-domain"] = self.sequence(self.prepending(plan.sniffingSkips, to: skipDomains))
        root["sniffer"] = .mapping(updated)
        return root
    }

    // MARK: - Helpers

    private static func whitelistRules(_ pattern: String) throws -> [String] {
        for (prefix, kind) in [("rule-set:", "RULE-SET"), ("geosite:", "GEOSITE")]
        where pattern.lowercased().hasPrefix(prefix) {
            let names = pattern.dropFirst(prefix.count).split(separator: ",", omittingEmptySubsequences: false)
            guard names.allSatisfy({ !$0.isEmpty }) else { throw ConfigError.invalidField("dns.fake-ip-filter") }
            return names.map { kind + "," + $0 + ",fake-ip" }
        }
        guard !pattern.isEmpty, !pattern.contains(",") else {
            throw ConfigError.invalidField("dns.fake-ip-filter")
        }
        if pattern == "*" { return ["MATCH,fake-ip"] }
        if pattern.hasPrefix("+.") {
            return ["DOMAIN-SUFFIX," + pattern.dropFirst(2) + ",fake-ip"]
        }
        if pattern.hasPrefix(".") {
            return ["DOMAIN-WILDCARD,*" + pattern + ",fake-ip"]
        }
        if pattern.contains("*") {
            return ["DOMAIN-WILDCARD," + pattern + ",fake-ip"]
        }
        return ["DOMAIN," + pattern + ",fake-ip"]
    }

    private static func mappingAny(root dns: Node.Mapping, field: String) throws -> Node.Mapping {
        guard let node = dns["nameserver-policy"], node.null == nil else { return Node.Mapping([]) }
        guard let mapping = node.mapping else { throw ConfigError.invalidField(field) }
        return mapping
    }

    private static func mapping(_ node: Node?, field: String) throws -> Node.Mapping {
        guard let node, node.null == nil else { return Node.Mapping([]) }
        guard let mapping = node.mapping else { throw ConfigError.invalidField(field) }
        return mapping
    }

    private static func strings(_ node: Node?, field: String) throws -> [String] {
        guard let node, node.null == nil else { return [] }
        guard let sequence = node.sequence else { throw ConfigError.invalidField(field) }
        return try sequence.map {
            guard let value = $0.scalar?.string else { throw ConfigError.invalidField(field) }
            return value
        }
    }

    private static func scalar(_ value: String) -> Node { Node(value, Tag(.str), .doubleQuoted) }
    private static func sequence(_ values: [String]) -> Node { Node(values.map(self.scalar)) }

    private static func prepending(_ required: [String], to existing: [String]) -> [String] {
        required + existing.filter { !required.contains($0) }
    }
}

// MARK: - YAML normalization

private struct YAMLNormalizer {
    private var anchors: [String: Node] = [:]
    private var remainingNodes = 200_000

    init(root: Node) throws { try self.collectAnchors(root) }

    private mutating func collectAnchors(_ node: Node, depth: Int = 0) throws {
        guard depth < 64 else { throw RuntimeOverlay.ConfigError.invalidYAML }
        switch node {
        case let .scalar(value):
            if let anchor = value.anchor { self.anchors[anchor.rawValue] = node }
        case let .mapping(value):
            if let anchor = value.anchor { self.anchors[anchor.rawValue] = node }
            for pair in value {
                try self.collectAnchors(pair.key, depth: depth + 1)
                try self.collectAnchors(pair.value, depth: depth + 1)
            }
        case let .sequence(value):
            if let anchor = value.anchor { self.anchors[anchor.rawValue] = node }
            for child in value { try self.collectAnchors(child, depth: depth + 1) }
        case .alias:
            break
        }
    }

    mutating func expand(_ node: Node, depth: Int = 0, visiting: Set<String> = []) throws -> Node {
        self.remainingNodes -= 1
        guard depth < 64, self.remainingNodes >= 0 else { throw RuntimeOverlay.ConfigError.invalidYAML }
        switch node {
        case let .alias(value):
            let name = value.anchor.rawValue
            guard !visiting.contains(name), let target = self.anchors[name] else {
                throw RuntimeOverlay.ConfigError.invalidYAML
            }
            return try self.expand(target, depth: depth + 1, visiting: visiting.union([name]))
        case var .scalar(value):
            value.anchor = nil
            return .scalar(value)
        case let .sequence(value):
            let children = try value.map { try self.expand($0, depth: depth + 1, visiting: visiting) }
            return Node(children, value.tag, value.style)
        case let .mapping(value):
            var merged = Node.Mapping([])
            var explicit: [(Node, Node)] = []
            var explicitKeys: Set<Node> = []
            for pair in value {
                let child = try self.expand(pair.value, depth: depth + 1, visiting: visiting)
                if pair.key.tag == Tag(.merge) {
                    let mappings: [Node.Mapping]
                    if let mapping = child.mapping {
                        mappings = [mapping]
                    } else if let sequence = child.sequence {
                        mappings = try sequence.map {
                            guard let mapping = $0.mapping else { throw RuntimeOverlay.ConfigError.invalidYAML }
                            return mapping
                        }.reversed()
                    } else {
                        throw RuntimeOverlay.ConfigError.invalidYAML
                    }
                    for mapping in mappings {
                        for entry in mapping { merged[entry.key] = entry.value }
                    }
                } else {
                    let key = try self.expand(pair.key, depth: depth + 1, visiting: visiting)
                    guard explicitKeys.insert(key).inserted else {
                        throw RuntimeOverlay.ConfigError.invalidYAML
                    }
                    explicit.append((key, child))
                }
            }
            for (key, child) in explicit { merged[key] = child }
            merged.style = value.style
            return .mapping(merged)
        }
    }
}

// MARK: - Runtime copy

struct LocalCoreRuntimeConfig {
    struct Prepared {
        let url: URL
        let compatibilityFailure: Error?
    }

    /// Falls back to the source config when shaping is unsupported, so a future syntax change
    /// degrades to the previous behavior instead of blocking the core from starting.
    static func prepareResult(sourceURL: URL, workingDirectoryURL: URL) -> Prepared {
        do {
            return Prepared(
                url: try self.prepare(sourceURL: sourceURL, workingDirectoryURL: workingDirectoryURL),
                compatibilityFailure: nil)
        } catch {
            return Prepared(url: sourceURL, compatibilityFailure: error)
        }
    }

    static func prepare(sourceURL: URL, workingDirectoryURL: URL) throws -> URL {
        let source = try String(contentsOf: sourceURL, encoding: .utf8)
        let payload = try RuntimeOverlay.apply(source: source, plan: CoexistenceContext.shared.currentPlan())
        let state = workingDirectoryURL.resolvingSymlinksInPath().appendingPathComponent("state", isDirectory: true)
        let directory = state.appendingPathComponent("runtime-configs", isDirectory: true)
        let fileManager = FileManager.default
        try self.rejectSymlinks(in: [state, directory])
        try fileManager.createDirectory(
            at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try self.rejectSymlinks(in: [state, directory])
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        let runtimeURL = directory.appendingPathComponent(sourceURL.lastPathComponent)
        // The private directory also protects the temporary file created by the atomic write.
        try Data(payload.utf8).write(to: runtimeURL, options: .atomic)
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: runtimeURL.path)
        return runtimeURL
    }

    private static func rejectSymlinks(in directories: [URL]) throws {
        for directory in directories {
            let attributes = try? FileManager.default.attributesOfItem(atPath: directory.path)
            if attributes?[.type] as? FileAttributeType == .typeSymbolicLink {
                throw RuntimeOverlay.ConfigError.invalidField("runtime-directory")
            }
        }
    }
}
