import Foundation

/// How a catalog entry decides whether it currently applies.
enum LocalEndpointActivation: Equatable, Sendable {
    /// Reserved endpoint that is harmless to protect even when the peer app is absent.
    case always
    /// Only when an interface whose name starts with this prefix exists.
    case whenInterfacePresent(prefix: String)
    /// Only when a network extension with this bundle identifier is enabled.
    case whenExtensionPresent(bundleIdentifier: String)
}

struct LocalEndpointRule: Equatable, Sendable {
    let id: String
    let displayName: String
    let domains: [String]
    /// CIDR blocks that must stay outside the tunnel.
    let addresses: [String]
    let activation: LocalEndpointActivation
    /// Domains whose resolution must be pinned to a fixed address.
    let pinnedHosts: [String: String]

    init(
        id: String,
        displayName: String,
        domains: [String] = [],
        addresses: [String] = [],
        activation: LocalEndpointActivation,
        pinnedHosts: [String: String] = [:])
    {
        self.id = id
        self.displayName = displayName
        self.domains = domains
        self.addresses = addresses
        self.activation = activation
        self.pinnedHosts = pinnedHosts
    }
}

/// Curated local endpoints that must keep their original network path.
enum LocalEndpointCatalog {
    static let adGuardLocalDomain = "local.adguard.org"
    static let adGuardLocalAddress = "94.140.14.247"
    static let tailscaleBundleIdentifier = "io.tailscale.ipn.macsys.network-extension"

    static let rules: [LocalEndpointRule] = [
        LocalEndpointRule(
            id: "adguard",
            displayName: "AdGuard",
            domains: ["local.adguard.org", "injections.adguard.org"],
            addresses: ["94.140.14.247/32"],
            // The reserved domain has no real server, so protecting it is a no-op when AdGuard is absent.
            activation: .always,
            pinnedHosts: ["local.adguard.org": "94.140.14.247"]),
        LocalEndpointRule(
            id: "tailscale",
            displayName: "Tailscale",
            domains: ["ts.net"],
            addresses: ["100.64.0.0/10", "100.100.100.100/32", "fd7a:115c:a1e0::/48"],
            // Excluding a CGNAT range unconditionally would break users who really route 100.64/10.
            activation: .whenExtensionPresent(
                bundleIdentifier: "io.tailscale.ipn.macsys.network-extension")),
        LocalEndpointRule(
            id: "zerotier",
            displayName: "ZeroTier",
            activation: .whenInterfacePresent(prefix: "feth")),
    ]
}
