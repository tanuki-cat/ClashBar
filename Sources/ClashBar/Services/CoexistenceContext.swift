import Foundation

/// Holds the exclusions plan currently in effect.
///
/// Written on the main actor when the network topology changes and read from the core
/// lifecycle queues, so access is serialized through a lock instead of an actor hop.
final class CoexistenceContext: @unchecked Sendable {
    static let shared = CoexistenceContext()

    private let lock = NSLock()
    private var plan: ExclusionPlan
    private var snapshot: CoexistenceSnapshot

    init(snapshot: CoexistenceSnapshot = .empty) {
        self.snapshot = snapshot
        self.plan = ExclusionPlanner.plan(
            snapshot: snapshot,
            catalog: LocalEndpointCatalog.rules,
            own: nil)
    }

    func currentPlan() -> ExclusionPlan {
        self.lock.lock()
        defer { self.lock.unlock() }
        return self.plan
    }

    func currentSnapshot() -> CoexistenceSnapshot {
        self.lock.lock()
        defer { self.lock.unlock() }
        return self.snapshot
    }

    /// Returns true when the derived plan actually changed.
    @discardableResult
    func update(snapshot: CoexistenceSnapshot, own: OwnTunInfo?) -> Bool {
        let updated = ExclusionPlanner.plan(
            snapshot: snapshot,
            catalog: LocalEndpointCatalog.rules,
            own: own)
        self.lock.lock()
        defer { self.lock.unlock() }
        let changed = updated != self.plan
        self.plan = updated
        self.snapshot = snapshot
        return changed
    }

    /// Test seam: restores the process-wide default.
    func reset(snapshot: CoexistenceSnapshot = .empty) {
        self.update(snapshot: snapshot, own: nil)
    }
}
