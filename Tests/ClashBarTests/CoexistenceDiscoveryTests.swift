import Foundation
import Testing
@testable import ClashBar

struct CoexistenceDiscoveryTests {
    private let tab = "\t"

    // MARK: - Extension parsing

    @Test func parsesEnabledNetworkExtensions() {
        let output = [
            "enabled" + self.tab + "active" + self.tab + "teamID" + self.tab + "bundleID (version)"
                + self.tab + "name" + self.tab + "[state]",
            "*" + self.tab + "*" + self.tab + "TC3Q7MAJXF" + self.tab
                + "com.adguard.mac.adguard.network-extension (2.20.2/2629)" + self.tab
                + "AdGuard Network Extension" + self.tab + "[activated enabled]",
            "*" + self.tab + "*" + self.tab + "W5364U7YZB" + self.tab
                + "io.tailscale.ipn.macsys.network-extension (1.102.2/101.102.2)" + self.tab
                + "Tailscale Network Extension" + self.tab + "[activated enabled]",
        ].joined(separator: "\n")
        let extensions = CoexistenceDiscovery.parseExtensions(output)
        let identifiers = extensions.map { $0.bundleIdentifier }
        #expect(identifiers.contains("com.adguard.mac.adguard.network-extension"))
        #expect(identifiers.contains("io.tailscale.ipn.macsys.network-extension"))
        #expect(extensions.allSatisfy { $0.isActive })
    }

    @Test func disabledExtensionsAreMarkedInactive() {
        let output = "*" + self.tab + "*" + self.tab + "W5364U7YZB" + self.tab
            + "io.tailscale.ipn.macsys.network-extension (1.0/1)" + self.tab + "Tailscale" + self.tab
            + "[activated disabled]"
        let extensions = CoexistenceDiscovery.parseExtensions(output)
        #expect(extensions.count == 1)
        #expect(extensions.first?.isActive == false)
    }

    @Test(arguments: ["", "garbage", "2 extension(s)"])
    func malformedExtensionOutputYieldsNothing(_ output: String) {
        #expect(CoexistenceDiscovery.parseExtensions(output).isEmpty)
    }

    // MARK: - Resolver parsing

    @Test func parsesScopedResolversWithInterfaceNames() {
        let output = [
            "DNS configuration",
            "",
            "resolver #1",
            "  search domain[0] : *",
            "  nameserver[0] : 8.8.8.8",
            "  flags    : Request A records",
            "",
            "DNS configuration (for scoped queries)",
            "",
            "resolver #1",
            "  search domain[0] : *",
            "  nameserver[0] : 8.8.8.8",
            "  if_index : 15 (en0)",
            "  flags    : Scoped, Request A records",
            "",
            "resolver #2",
            "  search domain[0] : tailnet.ts.net",
            "  nameserver[0] : 100.100.100.100",
            "  if_index : 24 (utun4)",
            "  flags    : Scoped, Request A records",
        ].joined(separator: "\n")
        let resolvers = CoexistenceDiscovery.parseResolvers(output)
        #expect(resolvers.count == 3)
        let tailscale = resolvers.first { $0.interfaceName == "utun4" }
        #expect(tailscale?.nameservers == ["100.100.100.100"])
        #expect(tailscale?.searchDomains == ["tailnet.ts.net"])
    }

    @Test func wildcardSearchDomainIsDropped() {
        let output = [
            "resolver #1",
            "  search domain[0] : *",
            "  nameserver[0] : 223.5.5.5",
            "  if_index : 15 (en0)",
        ].joined(separator: "\n")
        let resolvers = CoexistenceDiscovery.parseResolvers(output)
        #expect(resolvers.first?.searchDomains == [])
        #expect(resolvers.first?.interfaceName == "en0")
    }

    @Test func resolverWithoutNameserverIsDiscarded() {
        let output = [
            "resolver #1",
            "  domain   : local",
            "  options  : mdns",
            "  timeout  : 5",
            "resolver #2",
            "  nameserver[0] : 1.1.1.1",
        ].joined(separator: "\n")
        let resolvers = CoexistenceDiscovery.parseResolvers(output)
        #expect(resolvers.count == 1)
        #expect(resolvers.first?.nameservers == ["1.1.1.1"])
    }

    // MARK: - Snapshot assembly

    @Test func snapshotUsesInjectedRunnerInsteadOfTheSystem() {
        let snapshot = CoexistenceDiscovery.snapshot { executable, _ in
            if executable.contains("systemextensionsctl") {
                let line = "*" + self.tab + "*" + self.tab + "W5364U7YZB" + self.tab
                    + "io.tailscale.ipn.macsys.network-extension (1.0/1)" + self.tab + "Tailscale" + self.tab
                    + "[activated enabled]"
                return CoexistenceDiscovery.CommandOutput(text: line, exitCode: 0)
            }
            return CoexistenceDiscovery.CommandOutput(text: "", exitCode: 0)
        }
        #expect(snapshot.extensions.contains { $0.bundleIdentifier.hasPrefix("io.tailscale") })
        // Interfaces come from the real machine, so only invariants are asserted.
        #expect(snapshot.interfaces.allSatisfy { (0...128).contains($0.prefixLength) })
    }

    @Test func missingCommandDoesNotThrow() {
        let snapshot = CoexistenceDiscovery.snapshot { _, _ in nil }
        #expect(snapshot.extensions.isEmpty)
        #expect(snapshot.resolvers.isEmpty)
    }
}
