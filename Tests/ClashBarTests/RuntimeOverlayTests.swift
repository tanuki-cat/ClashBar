import Darwin
import Foundation
import Testing
import Yams
@testable import ClashBar

struct RuntimeOverlayTests {
    private var plan: ExclusionPlan {
        ExclusionPlanner.plan(snapshot: .empty, catalog: LocalEndpointCatalog.rules, own: nil)
    }

    private func output(_ source: String) throws -> Node {
        let payload = try RuntimeOverlay.apply(source: source, plan: self.plan)
        let node = try Yams.compose(yaml: payload)
        return try #require(node)
    }

    private func strings(_ node: Node?) -> [String] {
        node?.sequence?.compactMap { $0.scalar?.string } ?? []
    }

    @Test func protectsLocalEndpointWithoutChangingOtherDomains() throws {
        let root = try self.output("""
        mixed-port: 7890
        dns:
          enable: true
          nameserver: [https://dns.example/dns-query]
          fake-ip-filter: ['*.lan']
        hosts: {intranet.example: 192.168.1.5}
        rules:
          - DOMAIN-SUFFIX,adguard.org,Proxy
          - MATCH,Proxy
        """)
        #expect(root["mixed-port"]?.int == 7890)
        #expect(self.strings(root["dns"]?["nameserver"]) == ["https://dns.example/dns-query"])
        #expect(self.strings(root["dns"]?["fake-ip-filter"]) == self.plan.realDomains + ["*.lan"])
        #expect(root["hosts"]?["local.adguard.org"]?.string == "94.140.14.247")
        #expect(root["hosts"]?["intranet.example"]?.string == "192.168.1.5")
        #expect(self.strings(root["rules"]) == self.plan.directRules + [
            "DOMAIN-SUFFIX,adguard.org,Proxy", "MATCH,Proxy",
        ])
    }

    @Test func preservesExplicitTunAndDNSSettingsAndOtherExclusions() throws {
        let root = try self.output("""
        tun: {enable: false, stack: gvisor, auto-route: false, mtu: 1400, route-exclude-address: [10.1.0.0/16]}
        dns: {enable: false, use-hosts: false, enhanced-mode: redir-host}
        sniffer: {enable: false, skip-domain: ['+.example.com']}
        """)
        #expect(root["tun"]?["enable"]?.bool == false)
        #expect(root["tun"]?["auto-route"]?.bool == false)
        #expect(root["tun"]?["stack"]?.string == "gvisor")
        #expect(root["tun"]?["mtu"]?.int == 1400)
        #expect(self.strings(root["tun"]?["route-exclude-address"]) == self.plan.routeExclusions + ["10.1.0.0/16"])
        #expect(root["dns"]?["enable"]?.bool == false)
        #expect(root["dns"]?["use-hosts"]?.bool == false)
        #expect(root["dns"]?["enhanced-mode"]?.string == "redir-host")
        #expect(root["sniffer"]?["enable"]?.bool == false)
        #expect(self.strings(root["sniffer"]?["skip-domain"]) == self.plan.sniffingSkips + ["+.example.com"])
    }

    @Test func ruleModeExceptionPrecedesCatchAllWithoutReplacingRules() throws {
        let root = try self.output("""
        dns:
          fake-ip-filter-mode: rule
          fake-ip-filter: ['MATCH,fake-ip']
        """)
        #expect(root["dns"]?["fake-ip-filter-mode"]?.string == "rule")
        let expected = self.plan.realDomains.map { "DOMAIN," + $0 + ",real-ip" } + ["MATCH,fake-ip"]
        #expect(self.strings(root["dns"]?["fake-ip-filter"]) == expected)
    }

    @Test func whitelistConversionPreservesWildcardAndCollectionSemantics() throws {
        let root = try self.output("""
        dns:
          use-hosts: false
          fake-ip-filter-mode: whitelist
          fake-ip-filter: ['+.google.com', '*.example.com', 'rule-set:Private', 'geosite:cn,private', '*']
        """)
        #expect(root["dns"]?["use-hosts"]?.bool == false)
        #expect(root["dns"]?["fake-ip-filter-mode"]?.string == "rule")
        let expected = self.plan.realDomains.map { "DOMAIN," + $0 + ",real-ip" } + [
            "DOMAIN-SUFFIX,google.com,fake-ip", "DOMAIN-WILDCARD,*.example.com,fake-ip",
            "RULE-SET,Private,fake-ip", "GEOSITE,cn,fake-ip", "GEOSITE,private,fake-ip",
            "MATCH,fake-ip", "MATCH,real-ip",
        ]
        #expect(self.strings(root["dns"]?["fake-ip-filter"]) == expected)
    }

    @Test func resolvesAliasesAndMergePrecedenceWithoutChangingScalarText() throws {
        let root = try self.output("""
        base: &base {stack: mixed, mtu: 1500, route-exclude-address: [10.0.0.0/8]}
        override: &override {mtu: 1400}
        tun: {<<: [*override, *base], stack: gvisor}
        dns-base: &dns {nameserver: ['https://dns.example/dns-query'], fake-ip-filter: ['*.lan']}
        dns: *dns
        groups: [{name: on, enabled: false, password: '000123', url: 'https://example.com/#x'}]
        """)
        #expect(root["tun"]?["mtu"]?.int == 1400)
        #expect(root["tun"]?["stack"]?.string == "gvisor")
        #expect(self.strings(root["tun"]?["route-exclude-address"]) == self.plan.routeExclusions + ["10.0.0.0/8"])
        #expect(self.strings(root["dns"]?["fake-ip-filter"]) == self.plan.realDomains + ["*.lan"])
        #expect(self.strings(root["dns-base"]?["fake-ip-filter"]) == ["*.lan"])
        let group = try #require(root["groups"]?.sequence?.first)
        #expect(group["name"]?.scalar?.string == "on")
        #expect(group["password"]?.scalar?.string == "000123")
        #expect(group["url"]?.scalar?.string == "https://example.com/#x")
    }

    @Test func bundledTemplateKeepsProxyGroupsProvidersAndUnicode() throws {
        let project = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let source = try String(contentsOf: project.appendingPathComponent(
            "Sources/ClashBar/Resources/ConfigTemplates/ClashBar.yaml"), encoding: .utf8)
        let root = try self.output(source)
        #expect(root["proxy-groups"]?.sequence?.isEmpty == false)
        #expect(root["rule-providers"]?.mapping?.isEmpty == false)
        let filter = self.strings(root["dns"]?["fake-ip-filter"])
        #expect(filter.contains("local.adguard.org"))
        #expect(Array(self.strings(root["rules"]).prefix(self.plan.directRules.count)) == self.plan.directRules)
    }

    @Test func booleanSnifferShorthandIsLeftUntouched() throws {
        let root = try self.output("""
        sniffer: true
        rules: ['MATCH,DIRECT']
        """)
        #expect(root["sniffer"]?.bool == true)
    }

    @Test func explicitSnifferWithoutSkipDomainKeepsItsSettings() throws {
        let root = try self.output("""
        sniffer: {enable: true, override-destination: true}
        rules: ['MATCH,DIRECT']
        """)
        #expect(root["sniffer"]?["enable"]?.bool == true)
        #expect(root["sniffer"]?["override-destination"]?.bool == true)
        #expect(root["sniffer"]?["skip-domain"] == nil)
    }

    @Test func rootMergeIsSupported() throws {
        let root = try self.output("""
        base: &base
          dns: {fake-ip-filter: ['*.lan']}
          rules: ['MATCH,DIRECT']
        <<: *base
        """)
        #expect(self.strings(root["dns"]?["fake-ip-filter"]) == self.plan.realDomains + ["*.lan"])
        #expect(self.strings(root["rules"]).last == "MATCH,DIRECT")
    }

    @Test func repeatedApplicationDoesNotAccumulateExceptions() throws {
        let source = "dns: {fake-ip-filter: ['*.lan']}\nrules: ['MATCH,DIRECT']\n"
        let once = try RuntimeOverlay.apply(source: source, plan: self.plan)
        #expect(try RuntimeOverlay.apply(source: once, plan: self.plan) == once)
    }

    @Test func emptyPlanLeavesUserConfigSemanticsIntact() throws {
        let source = "dns: {fake-ip-filter: ['*.lan']}\nrules: ['MATCH,DIRECT']\n"
        let payload = try RuntimeOverlay.apply(source: source, plan: ExclusionPlan())
        let node = try Yams.compose(yaml: payload)
        let root = try #require(node)
        #expect(self.strings(root["dns"]?["fake-ip-filter"]) == ["*.lan"])
        #expect(self.strings(root["rules"]) == ["MATCH,DIRECT"])
        #expect(root["tun"] == nil)
        #expect(root["hosts"] == nil)
    }

    @Test func supportsJSONAndNullOptionalBlocks() throws {
        let root = try self.output(#"{"dns":null,"tun":null,"hosts":null,"rules":null}"#)
        #expect(self.strings(root["tun"]?["route-exclude-address"]) == self.plan.routeExclusions)
        #expect(self.strings(root["rules"]) == self.plan.directRules)
    }

    @Test(arguments: [
        "[]", "dns: [invalid]", "rules: not-a-list", "dns: {fake-ip-filter: {unexpected: value}}",
        "dns: {}\ndns: {}", "value: &cycle {nested: *cycle}", "dns: {fake-ip-filter-mode: unsupported}",
    ]) func rejectsUnsafeOrMalformedInput(_ source: String) {
        #expect(throws: RuntimeOverlay.ConfigError.self) {
            try RuntimeOverlay.apply(source: source, plan: self.plan)
        }
    }

    @Test func parserFailureDoesNotExposeCredentialSource() {
        do {
            _ = try RuntimeOverlay.apply(source: "password: sensitive-fixture-value\ndns: [", plan: self.plan)
            Issue.record("Expected invalid YAML")
        } catch {
            #expect(!error.localizedDescription.contains("sensitive-fixture-value"))
        }
    }

    @Test func createsPrivateRuntimeCopyWithoutEditingSubscription() throws {
        try self.withDirectory { directory in
            let sourceURL = directory.appendingPathComponent("subscription.yaml")
            let source = Data("# subscription comment\ndns: {enable: true}\nrules: ['MATCH,DIRECT']\n".utf8)
            try source.write(to: sourceURL)
            let runtimeURL = try LocalCoreRuntimeConfig.prepare(sourceURL: sourceURL, workingDirectoryURL: directory)
            #expect(try Data(contentsOf: sourceURL) == source)
            #expect(runtimeURL.lastPathComponent == sourceURL.lastPathComponent)
            #expect(runtimeURL.path.contains("/state/runtime-configs/"))
            let attributes = try FileManager.default.attributesOfItem(atPath: runtimeURL.path)
            #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
            let parentAttributes = try FileManager.default.attributesOfItem(
                atPath: runtimeURL.deletingLastPathComponent().path)
            #expect((parentAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o700)
            _ = try LocalCoreRuntimeConfig.prepare(sourceURL: sourceURL, workingDirectoryURL: directory)
            #expect(try Data(contentsOf: sourceURL) == source)
        }
    }

    @Test func unsupportedSourceDegradesToOriginalConfig() throws {
        try self.withDirectory { directory in
            let sourceURL = directory.appendingPathComponent("subscription.yaml")
            let source = Data("dns: {fake-ip-filter-mode: unknown-mode}\nrules: ['MATCH,DIRECT']\n".utf8)
            try source.write(to: sourceURL)
            let prepared = LocalCoreRuntimeConfig.prepareResult(
                sourceURL: sourceURL, workingDirectoryURL: directory)
            #expect(prepared.url == sourceURL)
            #expect(prepared.compatibilityFailure != nil)
            #expect(try Data(contentsOf: sourceURL) == source)
        }
    }

    @Test(arguments: ["state", "state/runtime-configs"])
    func rejectsSymlinkedRuntimeDirectory(_ linkPath: String) throws {
        try self.withDirectory { directory in
            let sourceURL = directory.appendingPathComponent("subscription.yaml")
            try Data("rules: ['MATCH,DIRECT']".utf8).write(to: sourceURL)
            let external = directory.appendingPathComponent("other", isDirectory: true)
            try FileManager.default.createDirectory(at: external, withIntermediateDirectories: true)
            if linkPath.contains("/") {
                try FileManager.default.createDirectory(
                    at: directory.appendingPathComponent("state"), withIntermediateDirectories: true)
            }
            try FileManager.default.createSymbolicLink(
                at: directory.appendingPathComponent(linkPath), withDestinationURL: external)
            #expect(throws: RuntimeOverlay.ConfigError.self) {
                try LocalCoreRuntimeConfig.prepare(sourceURL: sourceURL, workingDirectoryURL: directory)
            }
        }
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["CLASHBAR_MIHOMO_TEST_BINARY"] != nil))
    func generatedConfigPassesNativeCoreValidation() throws {
        let binary = try #require(ProcessInfo.processInfo.environment["CLASHBAR_MIHOMO_TEST_BINARY"])
        try self.withDirectory { directory in
            let sourceURL = directory.appendingPathComponent("fixture.yaml")
            try Data("""
            mixed-port: 0
            dns:
              enable: true
              enhanced-mode: fake-ip
              nameserver: [223.5.5.5]
              fake-ip-filter-mode: whitelist
              fake-ip-filter: ['*']
            rules: ['MATCH,DIRECT']
            """.utf8).write(to: sourceURL)
            let runtimeURL = try LocalCoreRuntimeConfig.prepare(sourceURL: sourceURL, workingDirectoryURL: directory)
            let result = self.runCore(
                binary: binary, workDirectory: directory, configPath: runtimeURL.path, timeout: 60)
            #expect(result.code == 0, Comment(rawValue: String(result.output.suffix(600))))
        }
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["CLASHBAR_REAL_CONFIG_DIR"] != nil))
    func realSubscriptionConfigsSurviveNativeCoreValidation() throws {
        let binary = try #require(ProcessInfo.processInfo.environment["CLASHBAR_MIHOMO_TEST_BINARY"])
        let root = try #require(ProcessInfo.processInfo.environment["CLASHBAR_REAL_CONFIG_DIR"])
        let work = URL(fileURLWithPath: root)
        let configs = try FileManager.default.contentsOfDirectory(at: work, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "yaml" }
        try #require(!configs.isEmpty)
        for config in configs {
            let runtimeURL = try LocalCoreRuntimeConfig.prepare(sourceURL: config, workingDirectoryURL: work)
            // Cold caches on a flaky network can make the core take a minute; this asserts the
            // config is accepted, not that validation is fast.
            let result = self.runCore(
                binary: binary, workDirectory: work, configPath: runtimeURL.path, timeout: 120)
            #expect(
                result.code == 0,
                Comment(rawValue: "core rejected the merged runtime copy of "
                    + config.lastPathComponent + " (exit " + String(result.code) + "): "
                    + String(result.output.suffix(600))))
        }
    }

    // MARK: - Helpers

    private struct CoreRunResult {
        let code: Int32
        let output: String
    }

    /// Runs the core in validation mode only; the binary is copied without its setuid bit.
    private func runCore(
        binary: String, workDirectory: URL, configPath: String, timeout: TimeInterval) -> CoreRunResult
    {
        let testBinary = workDirectory.appendingPathComponent("mihomo-test")
        if !FileManager.default.fileExists(atPath: testBinary.path) {
            try? Data(contentsOf: URL(fileURLWithPath: binary)).write(to: testBinary)
            try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: testBinary.path)
        }
        let process = Process()
        process.executableURL = testBinary
        process.arguments = ["-d", workDirectory.path, "-f", configPath, "-t"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        let finished = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in finished.signal() }
        do {
            try process.run()
        } catch {
            return CoreRunResult(code: -1, output: error.localizedDescription)
        }
        guard finished.wait(timeout: .now() + timeout) == .success else {
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            _ = finished.wait(timeout: .now() + 1)
            return CoreRunResult(code: -2, output: "validation timed out")
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        return CoreRunResult(code: process.terminationStatus, output: output)
    }

    private func withDirectory(_ operation: (URL) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ClashBar-RuntimeOverlayTests-" + UUID().uuidString, isDirectory: true)
            .resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer {
            if directory.lastPathComponent.hasPrefix("ClashBar-RuntimeOverlayTests-") {
                try? FileManager.default.removeItem(at: directory)
            }
        }
        try operation(directory)
    }
}
