import Foundation

@MainActor
extension AppViewModel {
    static func tunNetworkRecoveryDelay(
        afterNetworkChange: Bool, lastAttempt: ContinuousClock.Instant?, now: ContinuousClock.Instant) -> Duration
    {
        guard afterNetworkChange, let lastAttempt else { return .seconds(1) }
        return max(.seconds(1), now.duration(to: lastAttempt.advanced(by: .seconds(10))))
    }

    func cancelTunNetworkRecovery() {
        self.tunNetworkRecoveryGeneration += 1
        self.tunNetworkRecoveryTask?.cancel()
        self.tunNetworkRecoveryTask = nil
    }

    func scheduleTunNetworkRecovery(afterNetworkChange: Bool = false) {
        self.cancelTunNetworkRecovery()
        guard !self.isRemoteTarget else { return }
        let expectedTunEnabled = self.isTunEnabled
        if afterNetworkChange, !expectedTunEnabled { return }
        let generation = self.tunNetworkRecoveryGeneration
        let controller = self.controller
        let delay = Self.tunNetworkRecoveryDelay(
            afterNetworkChange: afterNetworkChange, lastAttempt: self.lastTunNetworkRecoveryAt, now: .now)
        self.tunNetworkRecoveryTask = Task { [weak self] in
            do {
                try await Task.sleep(for: delay)
                guard let self else { return }
                defer {
                    if self.tunNetworkRecoveryGeneration == generation { self.tunNetworkRecoveryTask = nil }
                }
                let validate: @MainActor () throws -> Void = {
                    try Task.checkCancellation()
                    guard self.tunNetworkRecoveryGeneration == generation,
                          !self.isRemoteTarget, self.controller == controller,
                          self.isTunEnabled == expectedTunEnabled
                    else { throw CancellationError() }
                }
                // Let a startup overlay or a stack switch finish before flushing either cache.
                for _ in 0..<40 {
                    try validate()
                    if !self.isCoreActionProcessing, !self.isTunSyncing, !self.isDNSCacheFlushInFlight { break }
                    try await Task.sleep(for: .milliseconds(250))
                }
                try validate()
                guard !self.isCoreActionProcessing, !self.isTunSyncing, !self.isDNSCacheFlushInFlight else { return }
                if expectedTunEnabled {
                    guard self.isRuntimeRunning, self.networkReachabilityStatus != .offline else { return }
                }
                self.lastTunNetworkRecoveryAt = .now
                let failures = try await self.flushDNSCaches(
                    includeCore: expectedTunEnabled,
                    installHelperIfNeeded: false,
                    validate: validate)
                try validate()
                self.logDNSCacheFailures(failures, level: "warning")
                if failures.isEmpty {
                    self.appendLog(level: "info", message: self.tr("log.tun.dns_refreshed"))
                }
                guard expectedTunEnabled, let url = URL(string: self.defaultHealthcheckURL) else { return }
                for attempt in 0..<2 {
                    try validate()
                    guard self.isRuntimeRunning, self.networkReachabilityStatus != .offline else { return }
                    do {
                        try await TunConnectivityProbe.check(url: url)
                        try validate()
                        self.appendLog(level: "info", message: self.tr("log.tun.connectivity_ok"))
                        return
                    } catch {
                        try validate()
                        if attempt == 1 {
                            let diagnosis = await self.diagnoseTunConnectivity(url: url)
                            if diagnosis.verdict == .ok { return }
                            self.appendLog(
                                level: "warning",
                                message: self.tr("log.tun.connectivity_failed", error.localizedDescription))
                            self.logConnectivityDiagnosis(diagnosis)
                        } else {
                            try await Task.sleep(for: .seconds(1))
                        }
                    }
                }
            } catch is CancellationError {
                // A target or TUN state change invalidates the pending recovery.
            } catch {
                guard let self else { return }
                self.appendLog(level: "warning", message: self.tr("log.tun.recovery_failed", error.localizedDescription))
            }
        }
    }

    func flushDNSCaches(
        includeCore: Bool = true,
        installHelperIfNeeded: Bool,
        validate: @escaping @MainActor () throws -> Void = {}) async throws -> [DNSCacheRecovery.Failure]
    {
        let controller = self.controller
        let isRemote = self.isRemoteTarget
        let validateTarget: @MainActor () throws -> Void = {
            try Task.checkCancellation()
            try validate()
            guard self.controller == controller, self.isRemoteTarget == isRemote else { throw CancellationError() }
        }
        let core: DNSCacheRecovery.Operation = {
            try validateTarget()
            try await self.clientOrThrow().requestNoResponse(.flushDNSCache)
        }
        let system: DNSCacheRecovery.Operation = {
            try validateTarget()
            try await self.systemProxyService.flushSystemDNSCache(installIfNeeded: installHelperIfNeeded)
        }
        return try await DNSCacheRecovery.flush(core: includeCore ? core : nil, system: isRemote ? nil : system)
    }

    func logDNSCacheFailures(_ failures: [DNSCacheRecovery.Failure], level: String) {
        for failure in failures {
            let key = failure.stage == .core ? "log.dns.core_flush_failed" : "log.dns.system_flush_failed"
            self.appendLog(level: level, message: self.tr(key, failure.message))
        }
    }
}
