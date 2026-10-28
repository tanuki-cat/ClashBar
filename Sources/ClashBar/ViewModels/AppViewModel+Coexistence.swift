import Foundation

@MainActor
extension AppViewModel {
    var currentOwnTunInfo: OwnTunInfo? {
        guard let device = self.tunDeviceName, !device.isEmpty else { return nil }
        return OwnTunInfo(deviceName: device, subnets: self.tunSubnets)
    }

    /// Recomputes the exclusions plan from the live topology.
    /// - Returns: whether the effective plan changed.
    @discardableResult
    func refreshCoexistencePlan() async -> Bool {
        guard !self.isRemoteTarget else { return false }
        let own = self.currentOwnTunInfo
        let snapshot = await Task.detached(priority: .utility) {
            CoexistenceDiscovery.snapshot()
        }.value
        var options = PlannerOptions()
        options.includeConservativeDefaults = self.conservativeTunDefaultsEnabled
        let changed = CoexistenceContext.shared.update(snapshot: snapshot, own: own, options: options)
        if changed { self.logCoexistenceSummary(snapshot) }
        return changed
    }

    var conservativeTunDefaultsEnabled: Bool {
        self.defaults.bool(forKey: self.conservativeTunDefaultsKey)
    }

    /// Persists the switch and immediately re-derives the plan, reloading the core when it changes.
    func setConservativeTunDefaults(_ enabled: Bool) {
        self.defaults.set(enabled, forKey: self.conservativeTunDefaultsKey)
        Task { [weak self] in
            guard let self else { return }
            let changed = await self.refreshCoexistencePlan()
            guard changed, self.isRuntimeRunning else { return }
            self.scheduleCoexistenceApply()
        }
    }

    func logCoexistenceSummary(_ snapshot: CoexistenceSnapshot) {
        let activeExtensions = snapshot.extensions.filter { $0.isActive }.map { $0.displayName }
            .filter { !$0.isEmpty }
        let peers = snapshot.interfaces.map { $0.name }
        guard activeExtensions.isEmpty == false || peers.isEmpty == false else { return }
        let parts = activeExtensions + peers
        self.appendLog(
            level: "info",
            message: self.tr("log.coexistence.detected", parts.joined(separator: ", ")))
    }

    /// Applies a changed plan to a running core through the config reload path, which
    /// re-reads the runtime copy without restarting the process.
    func scheduleCoexistenceApply() {
        self.coexistenceApplyTask?.cancel()
        self.coexistenceApplyTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(2))
            guard let self, !Task.isCancelled else { return }
            guard !self.isRemoteTarget, self.isRuntimeRunning else { return }
            await self.reloadConfig()
        }
    }

    func handleCoexistenceTopologyChange() async {
        guard !self.isRemoteTarget else { return }
        let changed = await self.refreshCoexistencePlan()
        guard changed, self.isRuntimeRunning else { return }
        self.scheduleCoexistenceApply()
    }
}
