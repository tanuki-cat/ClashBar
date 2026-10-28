import Foundation
import Yams

enum AdGuardCompatibility {
    // AdGuard intercepts this reserved endpoint locally; it must retain the browser's network path.
    static let localDomain = "local.adguard.org"
    static let localAddress = "94.140.14.247"
    static let routeExclusion = "94.140.14.247/32"
    static let directRules = [
        "DOMAIN,local.adguard.org,DIRECT",
        "IP-CIDR,94.140.14.247/32,DIRECT,no-resolve",
    ]

    enum ConfigError: LocalizedError {
        case invalidYAML
        case invalidField(String)

        var errorDescription: String? {
            switch self {
            case .invalidYAML: "Unable to parse YAML for AdGuard compatibility."
            case let .invalidField(field): "Unsupported configuration field for AdGuard compatibility: \(field)"
            }
        }
    }

    static func applying(to source: String) throws -> String {
        let parsed: Node
        do {
            guard let node = try Yams.compose(yaml: source) else { throw ConfigError.invalidYAML }
            parsed = node
        } catch {
            // Parser errors can include credential-bearing source lines.
            throw ConfigError.invalidYAML
        }
        var normalizer = try YAMLNormalizer(root: parsed)
        var root = try normalizer.expand(parsed)
        guard root.mapping != nil else { throw ConfigError.invalidYAML }

        var dns = try self.mapping(root["dns"], field: "dns")
        let filter = try self.strings(dns["fake-ip-filter"], field: "dns.fake-ip-filter")
        let mode = dns["fake-ip-filter-mode"]?.string?.lowercased() ?? "blacklist"
        switch mode {
        case "blacklist":
            dns["fake-ip-filter"] = self.sequence(self.prepending([self.localDomain], to: filter))
        case "rule":
            dns["fake-ip-filter"] = self.sequence(self.prepending(
                ["DOMAIN,\(self.localDomain),real-ip"], to: filter))
        case "whitelist":
            // Preserve whitelist semantics, including wildcard and rule-set matches, below the local exception.
            dns["fake-ip-filter-mode"] = self.scalar("rule")
            dns["fake-ip-filter"] = self.sequence(
                ["DOMAIN,\(self.localDomain),real-ip"] + (try filter.flatMap(self.whitelistRules)) + ["MATCH,real-ip"])
        default:
            throw ConfigError.invalidField("dns.fake-ip-filter-mode")
        }
        root["dns"] = .mapping(dns)

        var hosts = try self.mapping(root["hosts"], field: "hosts")
        hosts[self.localDomain] = self.scalar(self.localAddress)
        root["hosts"] = .mapping(hosts)

        var tun = try self.mapping(root["tun"], field: "tun")
        let exclusions = try self.strings(tun["route-exclude-address"], field: "tun.route-exclude-address")
        tun["route-exclude-address"] = self.sequence(self.prepending([self.routeExclusion], to: exclusions))
        root["tun"] = .mapping(tun)

        let rules = try self.strings(root["rules"], field: "rules")
        root["rules"] = self.sequence(self.prepending(self.directRules, to: rules))
        if let snifferNode = root["sniffer"], snifferNode.null == nil {
            // `sniffer: true` is a valid shorthand: only override an explicit domain list.
            if let sniffer = snifferNode.mapping, sniffer["skip-domain"] != nil {
                var updated = sniffer
                let skipDomains = try self.strings(sniffer["skip-domain"], field: "sniffer.skip-domain")
                updated["skip-domain"] = self.sequence(self.prepending([self.localDomain], to: skipDomains))
                root["sniffer"] = .mapping(updated)
            }
        }
        return try Yams.serialize(node: root, allowUnicode: true)
    }

    private static func whitelistRules(_ pattern: String) throws -> [String] {
        for (prefix, kind) in [("rule-set:", "RULE-SET"), ("geosite:", "GEOSITE")] where pattern.lowercased().hasPrefix(prefix) {
            let names = pattern.dropFirst(prefix.count).split(separator: ",", omittingEmptySubsequences: false)
            guard names.allSatisfy({ !$0.isEmpty }) else { throw ConfigError.invalidField("dns.fake-ip-filter") }
            return names.map { "\(kind),\($0),fake-ip" }
        }
        guard !pattern.isEmpty, !pattern.contains(",") else {
            throw ConfigError.invalidField("dns.fake-ip-filter")
        }
        if pattern == "*" { return ["MATCH,fake-ip"] }
        if pattern.hasPrefix("+.") { return ["DOMAIN-SUFFIX,\(pattern.dropFirst(2)),fake-ip"] }
        if pattern.hasPrefix(".") { return ["DOMAIN-WILDCARD,*\(pattern),fake-ip"] }
        if pattern.contains("*") { return ["DOMAIN-WILDCARD,\(pattern),fake-ip"] }
        return ["DOMAIN,\(pattern),fake-ip"]
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

private struct YAMLNormalizer {
    private var anchors: [String: Node] = [:]
    private var remainingNodes = 200_000

    init(root: Node) throws { try self.collectAnchors(root) }

    private mutating func collectAnchors(_ node: Node, depth: Int = 0) throws {
        guard depth < 64 else { throw AdGuardCompatibility.ConfigError.invalidYAML }
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
        case .alias: break
        }
    }

    mutating func expand(_ node: Node, depth: Int = 0, visiting: Set<String> = []) throws -> Node {
        self.remainingNodes -= 1
        guard depth < 64, self.remainingNodes >= 0 else { throw AdGuardCompatibility.ConfigError.invalidYAML }
        switch node {
        case let .alias(value):
            let name = value.anchor.rawValue
            guard !visiting.contains(name), let target = self.anchors[name] else {
                throw AdGuardCompatibility.ConfigError.invalidYAML
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
                    if let mapping = child.mapping { mappings = [mapping] }
                    else if let sequence = child.sequence {
                        mappings = try sequence.map {
                            guard let mapping = $0.mapping else { throw AdGuardCompatibility.ConfigError.invalidYAML }
                            return mapping
                        }.reversed()
                    } else { throw AdGuardCompatibility.ConfigError.invalidYAML }
                    for mapping in mappings { for entry in mapping { merged[entry.key] = entry.value } }
                } else {
                    let key = try self.expand(pair.key, depth: depth + 1, visiting: visiting)
                    guard explicitKeys.insert(key).inserted else { throw AdGuardCompatibility.ConfigError.invalidYAML }
                    explicit.append((key, child))
                }
            }
            for (key, child) in explicit { merged[key] = child }
            merged.style = value.style
            return .mapping(merged)
        }
    }
}

struct LocalCoreRuntimeConfig {
    struct Prepared {
        let url: URL
        let compatibilityFailure: Error?
    }

    /// Uses the source config unchanged when compatibility shaping is unsupported, so a future
    /// syntax change degrades to the previous behavior instead of blocking the core from starting.
    static func prepareResult(sourceURL: URL, workingDirectoryURL: URL) -> Prepared {
        do {
            return Prepared(url: try self.prepare(sourceURL: sourceURL, workingDirectoryURL: workingDirectoryURL),
                            compatibilityFailure: nil)
        } catch {
            return Prepared(url: sourceURL, compatibilityFailure: error)
        }
    }

    static func prepare(sourceURL: URL, workingDirectoryURL: URL) throws -> URL {
        let source = try String(contentsOf: sourceURL, encoding: .utf8)
        let payload = try AdGuardCompatibility.applying(to: source)
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
                throw AdGuardCompatibility.ConfigError.invalidField("runtime-directory")
            }
        }
    }
}
