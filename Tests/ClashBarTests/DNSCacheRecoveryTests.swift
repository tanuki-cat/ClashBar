import Foundation
import Testing
@testable import ClashBar

@MainActor
struct DNSCacheRecoveryTests {
    @Test func flushesCoreThenSystem() async throws {
        var calls: [String] = []
        let failures = try await DNSCacheRecovery.flush(
            core: { calls.append("core") },
            system: { calls.append("system") })
        #expect(calls == ["core", "system"])
        #expect(failures.isEmpty)
    }

    @Test func coreFailureDoesNotSkipSystemFlush() async throws {
        var systemFlushed = false
        let failures = try await DNSCacheRecovery.flush(
            core: { throw URLError(.cannotConnectToHost) },
            system: { systemFlushed = true })
        #expect(systemFlushed)
        #expect(failures.map(\.stage) == [.core])
    }

    @Test func reportsBothFailuresWithoutClaimingSuccess() async throws {
        let failures = try await DNSCacheRecovery.flush(
            core: { throw URLError(.cannotConnectToHost) },
            system: { throw SystemProxyServiceError.helperNotRegistered })
        #expect(failures.map(\.stage) == [.core, .system])
    }

    @Test func remoteFlushOnlyRunsCoreOperation() async throws {
        var coreFlushed = false
        let failures = try await DNSCacheRecovery.flush(core: { coreFlushed = true }, system: nil)
        #expect(coreFlushed)
        #expect(failures.isEmpty)
    }

    @Test func tunDisableCanFlushSystemWithoutCore() async throws {
        var systemFlushed = false
        let failures = try await DNSCacheRecovery.flush(core: nil, system: { systemFlushed = true })
        #expect(systemFlushed)
        #expect(failures.isEmpty)
    }

    @Test func cancellationSkipsSystemFlush() async throws {
        var systemFlushed = false
        do {
            _ = try await DNSCacheRecovery.flush(
                core: { throw CancellationError() },
                system: { systemFlushed = true })
            Issue.record("Expected cancellation")
        } catch is CancellationError {
            #expect(!systemFlushed)
        }
    }

    @Test func cancelledTaskDoesNotStartEitherOperation() async throws {
        var calls = 0
        let task = Task { @MainActor in
            _ = try await DNSCacheRecovery.flush(core: { calls += 1 }, system: { calls += 1 })
        }
        task.cancel()
        do {
            try await task.value
            Issue.record("Expected cancellation")
        } catch is CancellationError {
            #expect(calls == 0)
        }
    }

    @Test func networkChangesAreDebouncedAndRateLimited() {
        let now = ContinuousClock.now
        #expect(AppViewModel.tunNetworkRecoveryDelay(
            afterNetworkChange: true, lastAttempt: nil, now: now) == .seconds(1))
        #expect(AppViewModel.tunNetworkRecoveryDelay(
            afterNetworkChange: true, lastAttempt: now, now: now) == .seconds(10))
        #expect(AppViewModel.tunNetworkRecoveryDelay(
            afterNetworkChange: true, lastAttempt: now.advanced(by: .seconds(-20)), now: now) == .seconds(1))
        #expect(AppViewModel.tunNetworkRecoveryDelay(
            afterNetworkChange: false, lastAttempt: now, now: now) == .seconds(1))
    }

    @Test func probeBypassesSystemProxyAndHasBoundedTimeout() {
        let configuration = TunConnectivityProbe.configuration()
        #expect(configuration.connectionProxyDictionary?.isEmpty == true)
        #expect(configuration.timeoutIntervalForRequest == 5)
        #expect(configuration.timeoutIntervalForResource == 5)
        #expect(configuration.urlCache == nil)
        #expect(!configuration.waitsForConnectivity)
    }

    @Test func watchesGlobalAndScopedDNSAndRoutesButNotProxySettings() throws {
        let patterns = try NetworkReachabilityMonitor.configurationPatterns.map { try NSRegularExpression(pattern: $0) }
        func matches(_ key: String) -> Bool {
            patterns.contains { $0.firstMatch(in: key, range: NSRange(key.startIndex..., in: key)) != nil }
        }
        #expect(matches("State:/Network/Global/DNS"))
        #expect(matches("State:/Network/Global/IPv4"))
        #expect(matches("State:/Network/Service/tailscale/DNS"))
        #expect(matches("State:/Network/Service/adguard/IPv6"))
        #expect(!matches("State:/Network/Global/Proxies"))
        #expect(!matches("State:/Network/Service/test/DNS/Unrelated"))
    }
}
