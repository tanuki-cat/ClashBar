import Foundation
import Testing
@testable import ClashBar

struct ConnectivityDiagnosisTests {
    @Test func reachableEndpointIsHealthy() {
        let diagnosis = ConnectivityDiagnosis.evaluate(
            endpointReachable: true, rawAddressReachable: false, peerInterceptors: [])
        #expect(diagnosis.verdict == .ok)
    }

    @Test func totalFailurePointsAtTheNetwork() {
        let diagnosis = ConnectivityDiagnosis.evaluate(
            endpointReachable: false, rawAddressReachable: false, peerInterceptors: ["AdGuard"])
        #expect(diagnosis.verdict == .networkUnreachable)
    }

    @Test func rawIpWorksWhileNamesFailWithPeerPresent() {
        let diagnosis = ConnectivityDiagnosis.evaluate(
            endpointReachable: false, rawAddressReachable: true, peerInterceptors: ["AdGuard", "Tailscale"])
        #expect(diagnosis.verdict == .dnsInterception(["AdGuard", "Tailscale"]))
    }

    @Test func rawIpWorksWithoutPeersBlamesDNSConfiguration() {
        let diagnosis = ConnectivityDiagnosis.evaluate(
            endpointReachable: false, rawAddressReachable: true, peerInterceptors: [])
        #expect(diagnosis.verdict == .resolutionFailure)
    }

    @Test func closedLocalPortIsNotReachable() {
        #expect(!TCPReachabilityProbe.canConnect(host: "127.0.0.1", port: 1, timeout: 1))
    }

    // Name resolution is intentionally not asserted here: when the system resolver is
    // intercepted, arbitrary names still answer, which would make such a test flaky.
}
