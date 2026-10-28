import Foundation
import Testing
@testable import ClashBar

struct ExclusionPlannerTests {
    private func plan(
        snapshot: CoexistenceSnapshot = .empty,
        catalog: [LocalEndpointRule] = LocalEndpointCatalog.rules,
        own: OwnTunInfo? = nil) -> ExclusionPlan
    {
        ExclusionPlanner.plan(snapshot: snapshot, catalog: catalog, own: own)
    }

    private func rule(id: String, addresses: [String] = [], domains: [String] = []) -> LocalEndpointRule {
        LocalEndpointRule(id: id, displayName: id, domains: domains, addresses: addresses, activation: .always)
    }

    // MARK: - Catalog activation

    @Test func reservedEndpointIsProtectedEvenWithoutPeerSoftware() {
        let plan = self.plan()
        #expect(plan.routeExclusions == ["94.140.14.247/32"])
        #expect(plan.realDomains == ["local.adguard.org", "injections.adguard.org"])
        #expect(plan.hostPins["local.adguard.org"] == "94.140.14.247")
        #expect(plan.directRules.contains("DOMAIN,local.adguard.org,DIRECT"))
        #expect(plan.directRules.contains("IP-CIDR,94.140.14.247/32,DIRECT,no-resolve"))
    }

    @Test func cgnatRangeStaysUntouchedWhileTailscaleIsAbsent() {
        let plan = self.plan()
        #expect(!plan.routeExclusions.contains("100.64.0.0/10"))
        #expect(!plan.realDomains.contains("ts.net"))
    }

    @Test func tailscaleRangeIsExcludedOnlyWhenItsExtensionIsEnabled() {
        let snapshot = CoexistenceSnapshot(extensions: [
            DetectedExtension(bundleIdentifier: LocalEndpointCatalog.tailscaleBundleIdentifier),
        ])
        let plan = self.plan(snapshot: snapshot)
        #expect(plan.routeExclusions.contains("100.64.0.0/10"))
        #expect(plan.routeExclusions.contains("100.100.100.100/32"))
        #expect(plan.routeExclusions.contains("fd7a:115c:a1e0::/48"))
        #expect(plan.realDomains.contains("ts.net"))
        #expect(plan.directRules.contains("IP-CIDR,100.64.0.0/10,DIRECT,no-resolve"))
        #expect(plan.directRules.contains("IP-CIDR6,fd7a:115c:a1e0::/48,DIRECT,no-resolve"))
    }

    @Test func disabledExtensionDoesNotActivateRule() {
        let snapshot = CoexistenceSnapshot(extensions: [
            DetectedExtension(bundleIdentifier: LocalEndpointCatalog.tailscaleBundleIdentifier, isActive: false),
        ])
        #expect(!self.plan(snapshot: snapshot).routeExclusions.contains("100.64.0.0/10"))
    }

    @Test func interfaceTriggeredRuleFollowsInterfacePresence() {
        let inactive = self.plan(catalog: [
            LocalEndpointRule(id: "zt", displayName: "ZeroTier", activation: .whenInterfacePresent(prefix: "feth")),
        ])
        #expect(inactive.isEmpty)

        let active = self.plan(
            snapshot: CoexistenceSnapshot(interfaces: [
                DetectedInterface(name: "feth1949", family: .v4, address: "10.147.17.5", prefixLength: 24, routedSubnets: []),
            ]),
            catalog: [
                LocalEndpointRule(id: "zt", displayName: "ZeroTier", activation: .whenInterfacePresent(prefix: "feth")),
            ])
        #expect(ExclusionPlanner.isActive(
            LocalEndpointRule(id: "zt", displayName: "ZeroTier", activation: .whenInterfacePresent(prefix: "feth")),
            snapshot: CoexistenceSnapshot(interfaces: [
                DetectedInterface(name: "feth1949", family: .v4, address: "10.147.17.5", prefixLength: 24, routedSubnets: []),
            ])))
        #expect(active.isEmpty)
    }

    // MARK: - Dynamic interfaces

    @Test func peerInterfaceRoutesBecomeExclusions() {
        let snapshot = CoexistenceSnapshot(
            interfaces: [
                DetectedInterface(
                    name: "utun4", family: .v4, address: "100.100.1.2", prefixLength: 32,
                    routedSubnets: ["100.64.0.0/10"]),
            ])
        // Dynamic exclusions need our own interface name to tell peers apart.
        #expect(!self.plan(snapshot: snapshot).routeExclusions.contains("100.64.0.0/10"))
        let plan = self.plan(snapshot: snapshot, own: OwnTunInfo(deviceName: "utun9"))
        #expect(plan.routeExclusions.contains("100.64.0.0/10"))
    }

    @Test func ownTunnelNeverExcludesItself() {
        let snapshot = CoexistenceSnapshot(
            interfaces: [
                DetectedInterface(
                    name: "utun9", family: .v4, address: "198.18.0.1", prefixLength: 30,
                    routedSubnets: ["198.18.0.0/16"]),
                DetectedInterface(
                    name: "utun4", family: .v4, address: "100.100.1.2", prefixLength: 32,
                    routedSubnets: ["100.64.0.0/10"]),
            ])
        let plan = self.plan(snapshot: snapshot, own: OwnTunInfo(deviceName: "utun9", subnets: ["198.18.0.1/30"]))
        #expect(!plan.routeExclusions.contains("198.18.0.0/16"))
        #expect(plan.routeExclusions.contains("100.64.0.0/10"))
    }

    @Test func physicalInterfaceRoutesAreIgnored() {
        let snapshot = CoexistenceSnapshot(
            interfaces: [
                DetectedInterface(name: "en0", family: .v4, address: "192.168.30.9", prefixLength: 24,
                                  routedSubnets: ["192.168.30.0/24"]),
            ])
        #expect(!self.plan(snapshot: snapshot).routeExclusions.contains("192.168.30.0/24"))
    }

    // MARK: - Safety validation

    @Test(arguments: ["0.0.0.0/0", "127.0.0.1/32", "224.0.0.1/32", "169.254.1.1/32", "::/0", "fe80::1/64"])
    func destructiveOrUselessBlocksAreRejected(_ address: String) {
        let plan = self.plan(catalog: [self.rule(id: "bad", addresses: [address])])
        #expect(!plan.routeExclusions.contains(address))
    }

    @Test func blockCoveringPhysicalSubnetIsRejected() {
        let snapshot = CoexistenceSnapshot(physicalSubnets: ["192.168.30.0/24"])
        let plan = self.plan(
            snapshot: snapshot,
            catalog: [self.rule(id: "wide", addresses: ["192.168.0.0/16"])])
        #expect(!plan.routeExclusions.contains("192.168.0.0/16"))
    }

    @Test func entriesAreCappedPerCategory() {
        let addresses = (1...100).map { "10.0." + String($0) + ".0/24" }
        let plan = self.plan(catalog: [self.rule(id: "many", addresses: addresses, domains: addresses)])
        #expect(plan.routeExclusions.count <= ExclusionPlanner.maxEntriesPerCategory)
        #expect(plan.directRules.count <= ExclusionPlanner.maxEntriesPerCategory)
    }

    @Test func duplicateEntriesCollapse() {
        let plan = self.plan(catalog: [
            self.rule(id: "a", addresses: ["94.140.14.247/32"], domains: ["dup.example"]),
            self.rule(id: "b", addresses: ["94.140.14.247/32"], domains: ["dup.example"]),
        ])
        #expect(plan.routeExclusions == ["94.140.14.247/32"])
        #expect(plan.realDomains == ["dup.example"])
    }

    // MARK: - CIDR

    @Test func cidrParsingAndContainment() throws {
        let wide = try #require(CidrBlock("192.168.0.0/16"))
        let narrow = try #require(CidrBlock("192.168.30.0/24"))
        #expect(wide.contains(narrow))
        #expect(!narrow.contains(wide))
        #expect(CidrBlock("192.168.0.0/33") == nil)
        #expect(CidrBlock("not-an-address") == nil)
        #expect(CidrBlock("10.0.0.1")?.prefixLength == 32)
        #expect(CidrBlock("fd7a:115c:a1e0::/48")?.isIPv4 == false)
    }
}
