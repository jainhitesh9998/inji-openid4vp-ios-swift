public struct Credential : Codable {
    public let format: FormatType
    public let data: AnyCodable
    public let credentialId: String
    // CCP fork: the wallet's holder DID (did:jwk), supplied by the app layer.
    // Used as the VP holder when the credential itself carries no
    // credentialSubject.id (bearer credentials, e.g. veres.dev EMT), so VP
    // construction no longer fails with "Holder ID not available in the credential".
    public let walletHolder: String?

    public init(format: FormatType, data: AnyCodable, credentialId: String, walletHolder: String? = nil) {
          self.format = format
          self.data = data
          self.credentialId = credentialId
          self.walletHolder = walletHolder
      }
}
