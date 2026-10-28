import Foundation
import Network
import SystemConfiguration

enum NetworkReachabilityStatus: Equatable {
    case unknown
    case online
    case offline

    init(pathStatus: NWPath.Status) {
        if pathStatus == .satisfied {
            self = .online
        } else {
            self = .offline
        }
    }
}

final class NetworkReachabilityMonitor {
    typealias StatusHandler = @Sendable (NetworkReachabilityStatus) -> Void

    private let queue: DispatchQueue
    private var monitor: NWPathMonitor?
    private var configurationStore: SCDynamicStore?

    static let configurationPatterns = [
        "^State:/Network/Global/(DNS|IPv4|IPv6)$",
        "^State:/Network/Service/[^/]+/(DNS|IPv4|IPv6)$",
    ]

    private final class ConfigurationCallback: Sendable {
        let handler: @Sendable () -> Void

        init(handler: @escaping @Sendable () -> Void) { self.handler = handler }
    }

    init(queue: DispatchQueue = DispatchQueue(label: "com.clashbar.network-reachability", qos: .utility)) {
        self.queue = queue
    }

    deinit {
        self.stop()
    }

    func start(
        onConfigurationChange: @escaping @Sendable () -> Void = {},
        handler: @escaping StatusHandler)
    {
        self.stop()

        self.startConfigurationMonitoring(handler: onConfigurationChange)
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { path in
            handler(NetworkReachabilityStatus(pathStatus: path.status))
            onConfigurationChange()
        }
        monitor.start(queue: self.queue)
        self.monitor = monitor
    }

    private func startConfigurationMonitoring(handler: @escaping @Sendable () -> Void) {
        let callback = ConfigurationCallback(handler: handler)
        var context = SCDynamicStoreContext(
            version: 0,
            info: Unmanaged.passUnretained(callback).toOpaque(),
            retain: { info in
                _ = Unmanaged<ConfigurationCallback>.fromOpaque(info).retain()
                return info
            },
            release: { info in
                Unmanaged<ConfigurationCallback>.fromOpaque(info).release()
            },
            copyDescription: nil)
        guard let store = SCDynamicStoreCreate(nil, "com.clashbar.network-configuration" as CFString, { _, _, info in
            guard let info else { return }
            Unmanaged<ConfigurationCallback>.fromOpaque(info).takeUnretainedValue().handler()
        }, &context) else { return }
        guard SCDynamicStoreSetNotificationKeys(store, nil, Self.configurationPatterns as CFArray),
              SCDynamicStoreSetDispatchQueue(store, self.queue)
        else { return }
        self.configurationStore = store
    }

    func stop() {
        if let store = self.configurationStore {
            SCDynamicStoreSetDispatchQueue(store, nil)
        }
        self.configurationStore = nil
        self.monitor?.cancel()
        self.monitor = nil
    }
}
