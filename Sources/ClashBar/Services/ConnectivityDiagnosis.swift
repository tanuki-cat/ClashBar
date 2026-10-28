import Darwin
import Foundation

/// Classifies a failed tunnel probe into something the user can act on.
struct ConnectivityDiagnosis: Equatable, Sendable {
    enum Verdict: Equatable, Sendable {
        case ok
        /// Nothing reached the network, so the failure is not about DNS or interception.
        case networkUnreachable
        /// A raw IP connection works while name-based access fails and a peer interceptor is present.
        case dnsInterception([String])
        /// A raw IP connection works while name-based access fails without a peer interceptor.
        case resolutionFailure
    }

    let verdict: Verdict

    /// - Parameters:
    ///   - endpointReachable: full HTTPS request through the tunnel, using the system resolver.
    ///   - rawAddressReachable: TCP connect to a literal IP, which needs no name resolution.
    ///   - peerInterceptors: other network interceptors currently present on the machine.
    static func evaluate(
        endpointReachable: Bool,
        rawAddressReachable: Bool,
        peerInterceptors: [String]) -> ConnectivityDiagnosis
    {
        if endpointReachable { return ConnectivityDiagnosis(verdict: .ok) }
        guard rawAddressReachable else { return ConnectivityDiagnosis(verdict: .networkUnreachable) }
        if peerInterceptors.isEmpty {
            return ConnectivityDiagnosis(verdict: .resolutionFailure)
        }
        return ConnectivityDiagnosis(verdict: .dnsInterception(peerInterceptors))
    }
}

/// Single-shot TCP reachability check that never involves DNS.
enum TCPReachabilityProbe {
    static let defaultHost = "223.5.5.5"
    static let defaultPort: UInt16 = 443

    static func canConnect(host: String, port: UInt16, timeout: TimeInterval) -> Bool {
        var hints = addrinfo(
            ai_flags: 0,
            ai_family: AF_INET,
            ai_socktype: SOCK_STREAM,
            ai_protocol: IPPROTO_TCP,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil)
        var info: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &info) == 0, let info else { return false }
        defer { freeaddrinfo(info) }

        let descriptor = socket(info.pointee.ai_family, info.pointee.ai_socktype, info.pointee.ai_protocol)
        guard descriptor >= 0 else { return false }
        defer { close(descriptor) }

        let flags = fcntl(descriptor, F_GETFL, 0)
        _ = fcntl(descriptor, F_SETFL, flags | O_NONBLOCK)

        let result = connect(descriptor, info.pointee.ai_addr, info.pointee.ai_addrlen)
        if result == 0 { return true }
        guard errno == EINPROGRESS else { return false }

        var writeSet = fd_set()
        self.setBit(descriptor, set: &writeSet)
        var timeval = timeval(tv_sec: Int(timeout), tv_usec: 0)
        let ready = select(descriptor + 1, nil, &writeSet, nil, &timeval)
        guard ready > 0 else { return false }

        var error: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &error, &length) == 0 else { return false }
        return error == 0
    }

    private static func setBit(_ descriptor: Int32, set: inout fd_set) {
        let offset = Int(descriptor) / 32
        let mask = Int32(1) << (Int(descriptor) % 32)
        withUnsafeMutablePointer(to: &set.fds_bits) { pointer in
            pointer.withMemoryRebound(to: Int32.self, capacity: 32) { bits in
                bits[offset] |= mask
            }
        }
    }
}
