import Foundation
import Testing
@testable import ClashBar

/// Guards the .strings files: a missing semicolon or a mismatched format specifier
/// only shows up at runtime, and silently degrades to the raw key.
struct LocalizationResourceTests {
    private struct Entry {
        let key: String
        let value: String
        let line: Int
    }

    private var localizationDirectory: URL {
        let project = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        return project.appendingPathComponent("Sources/ClashBar/Resources/Localization")
    }

    private func languages() throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: self.localizationDirectory.path)
            .filter { $0.hasSuffix(".lproj") }
            .map { String($0.dropLast(".lproj".count)) }
            .sorted()
    }

    private func source(_ language: String) throws -> String {
        let url = self.localizationDirectory
            .appendingPathComponent(language + ".lproj")
            .appendingPathComponent("Localizable.strings")
        return try String(contentsOf: url, encoding: .utf8)
    }

    /// Parses the file and reports the first syntax problem, if any.
    private func entries(_ language: String) throws -> (entries: [Entry], malformed: [(Int, String)]) {
        var parsed: [Entry] = []
        var malformed: [(Int, String)] = []
        let pattern = "^\"([^\"]+)\" = \"(.*)\";$"
        let regex = try NSRegularExpression(pattern: pattern)
        for (index, rawLine) in try self.source(language).split(separator: "\n", omittingEmptySubsequences: false)
            .enumerated()
        {
            let line = String(rawLine).trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("//") { continue }
            let range = NSRange(line.startIndex..<line.endIndex, in: line)
            guard let match = regex.firstMatch(in: line, range: range),
                  let keyRange = Range(match.range(at: 1), in: line),
                  let valueRange = Range(match.range(at: 2), in: line)
            else {
                malformed.append((index + 1, line))
                continue
            }
            parsed.append(Entry(key: String(line[keyRange]), value: String(line[valueRange]), line: index + 1))
        }
        return (parsed, malformed)
    }

    private func formatSpecifiers(_ value: String) -> [String] {
        let regex = try? NSRegularExpression(pattern: "%[@difs%]")
        let range = NSRange(value.startIndex..<value.endIndex, in: value)
        return (regex?.matches(in: value, range: range) ?? []).compactMap { match in
            Range(match.range, in: value).map { String(value[$0]) }
        }.filter { $0 != "%%" }
    }

    @Test func everyLineIsWellFormed() throws {
        for language in try self.languages() {
            let result = try self.entries(language)
            #expect(
                result.malformed.isEmpty,
                Comment(rawValue: language + " malformed lines: "
                    + result.malformed.map { "line " + String($0.0) + ": " + $0.1 }.joined(separator: " | ")))
        }
    }

    @Test func keysAreUnique() throws {
        for language in try self.languages() {
            let entries = try self.entries(language).entries
            var seen: Set<String> = []
            let duplicates = entries.filter { !seen.insert($0.key).inserted }.map { $0.key }
            #expect(duplicates.isEmpty, Comment(rawValue: language + " duplicate keys: " + duplicates.joined(separator: ", ")))
        }
    }

    @Test func languagesDefineTheSameKeys() throws {
        let all = try self.languages()
        let reference = try #require(all.first)
        let referenceKeys = Set(try self.entries(reference).entries.map { $0.key })
        for language in all.dropFirst() {
            let keys = Set(try self.entries(language).entries.map { $0.key })
            let missing = referenceKeys.subtracting(keys).sorted()
            let extra = keys.subtracting(referenceKeys).sorted()
            #expect(missing.isEmpty, Comment(rawValue: language + " missing: " + missing.joined(separator: ", ")))
            #expect(extra.isEmpty, Comment(rawValue: language + " extra: " + extra.joined(separator: ", ")))
        }
    }

    @Test func formatSpecifiersMatchAcrossLanguages() throws {
        let all = try self.languages()
        let reference = try #require(all.first)
        let referenceMap = Dictionary(
            try self.entries(reference).entries.map { ($0.key, self.formatSpecifiers($0.value)) },
            uniquingKeysWith: { first, _ in first })
        for language in all.dropFirst() {
            for entry in try self.entries(language).entries {
                guard let expected = referenceMap[entry.key] else { continue }
                #expect(
                    self.formatSpecifiers(entry.value) == expected,
                    Comment(rawValue: language + " placeholder mismatch for " + entry.key))
            }
        }
    }
}
