import Foundation

internal struct CredentialInputDescriptorMapping {
    let format: FormatType
    let credential: AnyCodable
    let inputDescriptorId: String
    // Optional Identifier - unique identifier for the credential, used for mapping to unsignedVpToken to its related VPTokenSigningResult
    // Example: UUID of the credential for SD-JWT, docType of the credential for mDoc
    var identifier: String?
    // Optional nested path - Pointer to the location of the credential within a VP
    // Example: for `ldp_vc` - "$.verifiableCredential[0]" -> the first credential in the verifiableCredential array of the VP Token contains the credential for the input descriptor id
    var nestedPath: String?
    // CCP fork: wallet holder DID fallback for credentials without credentialSubject.id.
    var walletHolder: String?

    init(format: FormatType, credential: AnyCodable, inputDescriptorId: String, identifier: String? = nil, nestedPath: String? = nil, walletHolder: String? = nil) {
        self.format = format
        self.credential = credential
        self.inputDescriptorId = inputDescriptorId
        self.identifier = identifier
        self.nestedPath = nestedPath
        self.walletHolder = walletHolder
    }
}
