import Foundation
import Testing
@testable import ClashBarProxyHelper

struct SystemDNSCacheFlusherTests {
    @Test func runsOnlyFixedCacheFlushCommandsInOrder() throws {
        var commands: [SystemDNSCacheFlusher.Command] = []
        try SystemDNSCacheFlusher.flush { commands.append($0) }
        #expect(commands == [
            .init(executable: "/usr/bin/dscacheutil", arguments: ["-flushcache"]),
            .init(executable: "/usr/bin/killall", arguments: ["-HUP", "mDNSResponder"]),
        ])
    }

    @Test func propagatesCommandFailure() throws {
        var calls = 0
        do {
            try SystemDNSCacheFlusher.flush { _ in
                calls += 1
                throw URLError(.noPermissionsToReadFile)
            }
            Issue.record("Expected command failure")
        } catch let error as URLError {
            #expect(error.code == .noPermissionsToReadFile)
            #expect(calls == 1)
        }
    }
}
