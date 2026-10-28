import Foundation

@MainActor
extension AppViewModel {
    /// Explains a failed tunnel probe instead of reporting a generic failure.
    func diagnoseTunConnectivity(url: URL) async -> ConnectivityDiagnosis {
        let peerInterceptors = CoexistenceContext.shared.currentSnapshot().extensions
            .filter { $0.isActive }
            .map { $0.displayName }
            .filter { !$0.isEmpty }

        let rawReachable = await Task.detached(priority: .utility) {
            TCPReachabilityProbe.canConnect(
                host: TCPReachabilityProbe.defaultHost,
                port: TCPReachabilityProbe.defaultPort,
                timeout: 3)
        }.value

        var endpointReachable = false
        do {
            try await TunConnectivityProbe.check(url: url)
            endpointReachable = true
        } catch {
            endpointReachable = false
        }
        return ConnectivityDiagnosis.evaluate(
            endpointReachable: endpointReachable,
            rawAddressReachable: rawReachable,
            peerInterceptors: peerInterceptors)
    }

    func logConnectivityDiagnosis(_ diagnosis: ConnectivityDiagnosis) {
        switch diagnosis.verdict {
        case .ok:
            return
        case .networkUnreachable:
            self.appendLog(level: "warning", message: self.tr("log.diagnosis.network_unreachable"))
        case let .dnsInterception(peers):
            self.appendLog(
                level: "warning",
                message: self.tr("log.diagnosis.dns_interception", peers.joined(separator: ", ")))
        case .resolutionFailure:
            self.appendLog(level: "warning", message: self.tr("log.diagnosis.resolution_failure"))
        }
    }
}
