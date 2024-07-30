import Testing

@testable import CommProtocol

struct SessionEncryptionSuitesTests {
    @Test func fixedEncoding() async throws {
        for suite in SessionEncryptionSuites.allCases {
            #expect(suite.fixedWidth.count == 2)
            let decoded = try SessionEncryptionSuites(fixedWidth: suite.fixedWidth)
            #expect(suite == decoded)
        }
    }
}
