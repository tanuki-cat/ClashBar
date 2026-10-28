import Foundation

@MainActor
enum DNSCacheRecovery {
    typealias Operation = @MainActor () async throws -> Void

    struct Failure: Sendable {
        enum Stage: Equatable, Sendable { case core, system }
        let stage: Stage
        let message: String
    }

    static func flush(core: Operation?, system: Operation?) async throws -> [Failure] {
        var failures: [Failure] = []
        for (stage, operation) in [(Failure.Stage.core, core), (.system, system)] {
            try Task.checkCancellation()
            guard let operation else { continue }
            do {
                try await operation()
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                try Task.checkCancellation()
                failures.append(Failure(stage: stage, message: error.localizedDescription))
            }
        }
        try Task.checkCancellation()
        return failures
    }
}

enum TunConnectivityProbe {
    static func configuration() -> URLSessionConfiguration {
        let configuration = URLSessionFactory.makeEphemeralConfiguration(options: .init(
            timeoutIntervalForRequest: 5,
            timeoutIntervalForResource: 5))
        // Exercise the system resolver and TUN path, not the HTTP/SOCKS system proxy.
        configuration.connectionProxyDictionary = [:]
        return configuration
    }

    static func check(url: URL) async throws {
        let session = URLSession(configuration: self.configuration())
        defer { session.invalidateAndCancel() }
        let (_, response) = try await session.data(from: url)
        guard let response = response as? HTTPURLResponse, response.statusCode == 204 else {
            throw URLError(.badServerResponse)
        }
    }
}
