internal struct DcqlEvaluator {
    private let className = "DcqlEvaluator"
    private let jsonLdExpander: JsonLdExpanderCallback?
    
    public init(jsonLdExpander: JsonLdExpanderCallback?) {
        self.jsonLdExpander = jsonLdExpander
    }
    
    internal func evaluate(_ dcqlQuery: DCQLQuery, inputCredentials: [Credential]) async throws -> MatchingCredentialsResult {
        var queryMatches: [String: QueryMatchResult] = [:]
        
        
        let credentialsByFormat = Dictionary(grouping: inputCredentials, by: { $0.format.rawValue })
        let credentialIdToCredential = Dictionary(
            inputCredentials.map { ($0.credentialId, $0) },
            uniquingKeysWith: { _, last in last }
        )
        
        // If any dcql query involves ldp_vc, jsonLd expander is required
        let requiresJsonLdExpander: Bool = dcqlQuery.credentials.contains(where: { $0.format == FormatType.ldp_vc.rawValue })
        
        if(requiresJsonLdExpander && jsonLdExpander == nil) {
            // If the query requires JSON-LD expansion but no expander is provided, we cannot evaluate the query
            throw UnsupportedOperationException(message: "JSON-LD expander is required but not provided", className: className)
        }
        
        // Local caches to ensure we only do work ONCE
        var credentialsTagCache: [String: TaggedCredential] = [:]
        var processedCredentialsCache: [String: any ProcessedCredential] = [:]
        
        for credentialQuery in dcqlQuery.credentials {
            // 1. Format check
            guard let formatMatchingCredentials = credentialsByFormat[credentialQuery.format], !formatMatchingCredentials.isEmpty else {
                queryMatches[credentialQuery.id] = QueryMatchResult(failureReason: .noMatchingFormatsFound, allowMultipleCredentials: credentialQuery.multiple)
                continue
            }
            
            // 2. Cryptographic Holder Binding and Meta check
            var metaAndBindingMatchingIds: [String] = []
            for credential in formatMatchingCredentials {
                let credentialId = credential.credentialId

                if credentialsTagCache[credentialId] == nil {
                    credentialsTagCache[credentialId] = try await expandCredentialTag(credential, jsonLdExpander: self.jsonLdExpander)
                }

                guard let credentialTag = credentialsTagCache[credentialId] else { continue }

                let holderBindingAndMetaMatchSuccess = matchesCryptographicHolderBinding(
                    dcqlQueryRequestsCryptograhicHolderBinding: credentialQuery.requireCryptographicHolderBinding,
                    walletCredential: credentialTag
                ) && matchesMeta(credentialQuery.meta, walletCredential: credentialTag)

                if holderBindingAndMetaMatchSuccess {
                    metaAndBindingMatchingIds.append(credentialId)
                }
            }
            
            if metaAndBindingMatchingIds.isEmpty {
                queryMatches[credentialQuery.id] = QueryMatchResult(failureReason: .cryptographicHolderBindingOrMetaFilterMismatch, allowMultipleCredentials: credentialQuery.multiple)
                continue
            }
            
            // 3. Claims level check
            let applicableInputCredentials = try getProcessedCredentials(
                matchingIds: metaAndBindingMatchingIds,
                credentialIdToCredential: credentialIdToCredential,
                processedCache: &processedCredentialsCache
            )
            
            queryMatches[credentialQuery.id] = try evaluateCredentialQueryClaims(credentialQuery, against: applicableInputCredentials)
        }
        
        let credentialSetRequirements = buildCredentialSetRequirements(dcqlQuery: dcqlQuery)
        let success = isQuerySatisfied(queryMatches: queryMatches, credentialSets: credentialSetRequirements, dcqlQuery: dcqlQuery)
        
        return MatchingCredentialsResult(success: success, queryMatches: queryMatches, credentialSets: credentialSetRequirements)
    }
    /**
     
     */
    
    /**
     * Processes missing credentials, caches them, and returns all credentials matching the provided IDs.
     */
    func getProcessedCredentials(
        matchingIds: [String],
        credentialIdToCredential: [String: Credential],
        processedCache: inout [String: any ProcessedCredential]
    ) throws -> [any ProcessedCredential] {
        let matchingIdsSet = Set(matchingIds)
        let nonProcessedIds = matchingIdsSet.filter { processedCache[$0] == nil }.map { String($0) }
        
        if !nonProcessedIds.isEmpty {
            let newProcessed = try convertToProcessedCredentials(nonProcessedIds, credentialIdToCredential)
            processedCache.merge(newProcessed) { (_, new) in new }
        }
        
        return matchingIds.compactMap { processedCache[$0] }
    }
    
    private func evaluateCredentialQueryClaims(_ credentialQuery: CredentialQuery, against walletCredentials: [any ProcessedCredential]) throws -> QueryMatchResult {
        if(credentialQuery.claims == nil) {
            // If no claims are requested, then all credentials that passed format, meta and holder binding checks are candidate credentials
            let matchingCredentials = walletCredentials.map { MatchingCredential(credentialId: $0.credentialId, matchingClaims: []) }
            return QueryMatchResult(matchingCredentials: matchingCredentials, allowMultipleCredentials: credentialQuery.multiple)
        }
        
        var matchingCredentials: [MatchingCredential] = []
        var failedClaims: [ClaimFailure] = []
        var failedClaimKeys = Set<String>()
        var claimsCheckFailureReason: DCQLEvaluationErrorCodes? = nil
        
        for credential in walletCredentials {
            let (matchingClaims, claimFailures, failureReason) = try evaluateClaims(credentialQuery: credentialQuery, walletCredential: credential)
            
            if claimFailures.isEmpty {
                matchingCredentials.append(MatchingCredential(credentialId: credential.credentialId, matchingClaims: matchingClaims))
            } else {
                if claimsCheckFailureReason == nil {
                    claimsCheckFailureReason = failureReason
                }
                for failure in claimFailures {
                    let deduplicationKey = "\(failure.reason):\(failure.claim.path.map { "\($0.value)" }.joined(separator: "."))"
                    if failedClaimKeys.insert(deduplicationKey).inserted {
                        failedClaims.append(failure)
                    }
                }
            }
        }
        
        if matchingCredentials.isEmpty {
            return QueryMatchResult(failedClaims: failedClaims.isEmpty ? nil : failedClaims, failureReason: claimsCheckFailureReason, allowMultipleCredentials: credentialQuery.multiple)
        }
        
        return QueryMatchResult(matchingCredentials: matchingCredentials, allowMultipleCredentials: credentialQuery.multiple)
    }
    
    // Evaluates claims and claim_sets
    private func evaluateClaims(credentialQuery: CredentialQuery, walletCredential: any ProcessedCredential) throws -> (matchingClaims: [ClaimsQuery], failedClaims: [ClaimFailure], failureReason: DCQLEvaluationErrorCodes?) {
        // If no claims is available in VP request, all mandatory claims of the credential needs to be shared to Verifier
        guard let claims = credentialQuery.claims else {
            return ([], [], nil)
        }
        
        // One of the options of the claim_sets needs to be satisfied if claim_sets is present in the VP request.
        
        if let claimSets = credentialQuery.claimSets {
            // claim_sets are ordered by preference, so we iterate through the options and return as soon as we find a satisfied option
            var failedClaimSetQuery: [ClaimFailure] = []
            for claimSetOption in claimSets {
                let requestedClaims = claims.filter { claimSetOption.contains($0.id ?? "") }
                let (matchingClaims, failedClaims) = try checkClaims(requestedClaims, walletCredential: walletCredential)
                
                // Once the claim_set option with all claims satisfied is found, return the result without evaluating further options as claim_sets are in order of preference
                if failedClaims.isEmpty {
                    return (matchingClaims, [], nil)
                }
                failedClaimSetQuery.append(contentsOf: failedClaims)
            }
            // Populate all claim failure reason
            return ([], failedClaimSetQuery, .noClaimsSetOptionSatisfied)
        }
        
        // If claim_sets is not present, then all claims in the VP request need to be satisfied
        let (matchingClaims, failedClaims) = try checkClaims(claims, walletCredential: walletCredential)
        if failedClaims.isEmpty {
            return (matchingClaims, [], nil)
        }
        // All-or-nothing: if any claim is missing/mismatched, the entire set fails.
        // Report all claims (including partially-matched ones) as failures.
        let allFailed = failedClaims + matchingClaims.map { ClaimFailure(claim: $0, reason: .claimUnavailable) }
        return ([], allFailed, .requiredClaimsNotSatisfied)
    }
    
    private func checkClaims(_ claims: [ClaimsQuery], walletCredential: any ProcessedCredential) throws -> (matchingClaims: [ClaimsQuery], failedClaims: [ClaimFailure]) {
        var matchingClaims: [ClaimsQuery] = []
        var failedClaims: [ClaimFailure] = []

        for claimQuery in claims {
            let resolved: Any?
            do {
                switch walletCredential {
                case let mdoc as MdocProcessedCredential:
                    resolved = try resolveClaimsPathPointer(claimQuery.path, in: mdoc.namespaces)
                case let w3c as W3cProcessedCredential:
                    resolved = try resolveClaimsPathPointer(claimQuery.path, in: w3c.claims)
                case let sdJwt as SdJwtProcessedCredential:
                    resolved = try resolveClaimsPathPointer(claimQuery.path, in: sdJwt.claims)
                default:
                    resolved = nil
                }
            } catch {
                resolved = nil
            }

            guard let resolved = resolved else {
                failedClaims.append(ClaimFailure(claim: claimQuery, reason: .claimUnavailable))
                continue
            }

            if let expectedClaimValues = claimQuery.values {
                if !matchesExpectedValues(resolved, expectedValues: expectedClaimValues) {
                    failedClaims.append(ClaimFailure(claim: claimQuery, reason: .claimValueMismatch))
                    continue
                }
            }

            matchingClaims.append(claimQuery)
        }

        return (matchingClaims, failedClaims)
    }
    
    private func matchesExpectedValues(_ claimValue: Any, expectedValues: [ClaimValue]) -> Bool {
        // A claim value can be an array (e.g. `type`, or any multi-valued field);
        // DCQL value matching is membership-based, so match if ANY element matches.
        if let claimArray = claimValue as? [Any] {
            return claimArray.contains { matchesExpectedValues($0, expectedValues: expectedValues) }
        }
        return expectedValues.contains { expected in
            switch expected {
            case .string(let v):
                return (claimValue as? String) == v
            case .int(let v):
                // Handle potential type mismatch if claimValue is parsed as Double from JSON
                if let actualInt = claimValue as? Int { return actualInt == v }
                if let actualDouble = claimValue as? Double { return Int(actualDouble) == v }
                return false
            case .bool(let v):
                return (claimValue as? Bool) == v
            }
        }
    }
    
    private func matchesMeta(_ meta: [String: AnyCodable], walletCredential: any TaggedCredential) -> Bool {
        if(meta.isEmpty) {
            return true
        }
        
        switch walletCredential {
        case let sdJwt as SdJwtTaggedCredential:
            if let vctValues = meta["vct_values"]?.value as? [String] {
                return vctValues.contains(sdJwt.vct)
            }
            return false
        case let mdoc as MdocTaggedCredential:
            if let doctypeValue = meta["doctype_value"]?.value as? String {
                return mdoc.doctype == doctypeValue
            }
            return false
        case let w3c as W3cTaggedCredential:
            if let typeValues = meta["type_values"]?.value as? [[String]] {
                return typeValues.contains { requiredTypes in
                    requiredTypes.allSatisfy { w3c.types.contains($0) }
                }
            }
            return false
        default:
            return false
        }
    }
    
    private func matchesCryptographicHolderBinding(dcqlQueryRequestsCryptograhicHolderBinding: Bool, walletCredential: any TaggedCredential) -> Bool {
        // require_cryptographic_holder_binding = false means the verifier accepts a credential without a holder binding proof.
        // require_cryptographic_holder_binding = true means the verifier accepts only credentials with a cryptographic holder binding proof.
        
        // A Verifiable Presentation with holder binding proof is possible only if credentials supports cryptographic holder binding and the wallet can produce the proof. Therefore, if require_cryptographic_holder_binding is true, we check if the credential supports holder binding and wallet can produce the proof; if false, we skip this check and consider the query satisfied even if the credential does not have a holder binding proof.
        
        return !dcqlQueryRequestsCryptograhicHolderBinding || walletCredential.hasCryptographicHolderBinding
    }
    
    // Builds CredentialSetRequirement array from dcqlQuery for the result
    private func buildCredentialSetRequirements(dcqlQuery: DCQLQuery) -> [CredentialSetQuery] {
        guard let credentialSets = dcqlQuery.credentialSets else {
            // Populate the credential set stating all - each credential query is required
            // Example - credentials: [{id: "id1"}, {id: "id2"}] -> credentialSets : [{options: ["id1"], required: true}, {options: ["id2"], required: true}]
            return dcqlQuery.credentials.map { CredentialSetQuery(options: [[$0.id]], required: true) }
        }
        return credentialSets
    }
    
    private func isQuerySatisfied(queryMatches: [String: QueryMatchResult], credentialSets: [CredentialSetQuery], dcqlQuery: DCQLQuery) -> Bool {
        if dcqlQuery.credentialSets == nil {
            // No credential_sets: all credential queries must be satisfied
            return queryMatches.values.allSatisfy { $0.matchingCredentials?.isEmpty == false }
        }
        
        // With credential_sets: all required sets must be satisfied; optional ones are ignored for success
        for credentialSet in credentialSets {
            guard credentialSet.required else { continue }
            
            let setIsSatisfied = credentialSet.options.contains { option in
                option.allSatisfy { credentialQueryId in
                    queryMatches[credentialQueryId]?.matchingCredentials?.isEmpty == false
                }
            }
            
            if !setIsSatisfied { return false }
        }
        
        return true
    }
    
}
