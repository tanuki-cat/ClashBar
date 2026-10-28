import Foundation
import Testing
@testable import ClashBar

struct CoexistenceContextTests {
    @Test func optionsShapeThePlanAndAreRemembered() {
        let context = CoexistenceContext()
        #expect(context.currentPlan().realSuffixes.isEmpty)

        var options = PlannerOptions()
        options.includeConservativeDefaults = true
        #expect(context.update(snapshot: .empty, own: nil, options: options))
        #expect(context.currentPlan().realSuffixes == ["local", "lan"])

        // Omitting the argument reuses the stored options instead of resetting them.
        #expect(context.update(snapshot: .empty, own: nil) == false)
        #expect(context.currentPlan().realSuffixes == ["local", "lan"])
    }

    @Test func disablingTheOptionRemovesTheSuffixes() {
        let context = CoexistenceContext()
        var enabled = PlannerOptions()
        enabled.includeConservativeDefaults = true
        context.update(snapshot: .empty, own: nil, options: enabled)

        #expect(context.update(snapshot: .empty, own: nil, options: PlannerOptions()))
        #expect(context.currentPlan().realSuffixes.isEmpty)
    }

    @Test func snapshotIsExposedForDiagnostics() {
        let context = CoexistenceContext()
        let snapshot = CoexistenceSnapshot(
            interfaces: [
                DetectedInterface(name: "utun4", family: .v4, address: "100.100.1.2", prefixLength: 32,
                                  routedSubnets: []),
            ],
            extensions: [DetectedExtension(bundleIdentifier: "com.example.vpn", displayName: "Example VPN")])
        context.update(snapshot: snapshot, own: OwnTunInfo(deviceName: "utun9"))
        #expect(context.currentSnapshot().extensions.first?.displayName == "Example VPN")
        #expect(context.currentSnapshot().interfaces.count == 1)
    }
}
