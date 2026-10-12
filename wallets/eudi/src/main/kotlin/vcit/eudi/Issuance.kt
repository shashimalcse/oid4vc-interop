/*
 * OpenID4VCI on the EUDI reference library eudi-lib-jvm-openid4vci-kt, authorization code flow:
 *
 *   POST /wallets/{id}/issuance/authorize {credentialIssuer, credentialConfigurationId, clientId, redirectUri}
 *        -> {ok, sessionId, authorizationUrl}       the caller logs the user in and follows the redirect
 *   POST /wallets/{id}/issuance/complete  {sessionId, code, state, iss?}
 *        -> {ok, credentialIds, credentials}         stored in the wallet for later presentation
 *
 * The wallet is a public OAuth client (the library supports no private_key_jwt). PAR and DPoP are
 * used when the issuer supports them; proofs are JWTs signed with the wallet's holder key.
 */
package vcit.eudi

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import eu.europa.ec.eudi.openid4vci.AuthorizationCode
import eu.europa.ec.eudi.openid4vci.AuthorizationRequestPrepared
import eu.europa.ec.eudi.openid4vci.BatchSignOperation
import eu.europa.ec.eudi.openid4vci.BatchSigner
import eu.europa.ec.eudi.openid4vci.CredentialConfigurationIdentifier
import eu.europa.ec.eudi.openid4vci.CredentialIssuerId
import eu.europa.ec.eudi.openid4vci.CredentialResponseEncryptionPolicy
import eu.europa.ec.eudi.openid4vci.DPoPConfig
import eu.europa.ec.eudi.openid4vci.DPoPUsage
import eu.europa.ec.eudi.openid4vci.EncryptionSupportConfig
import eu.europa.ec.eudi.openid4vci.HttpsUrl
import eu.europa.ec.eudi.openid4vci.IssuanceRequestPayload
import eu.europa.ec.eudi.openid4vci.Issuer
import eu.europa.ec.eudi.openid4vci.JwsAlgorithm
import eu.europa.ec.eudi.openid4vci.JwtBindingKey
import eu.europa.ec.eudi.openid4vci.OpenId4VCIConfig
import eu.europa.ec.eudi.openid4vci.ParUsage
import eu.europa.ec.eudi.openid4vci.ProofSpecification
import eu.europa.ec.eudi.openid4vci.ProofsConfig
import eu.europa.ec.eudi.openid4vci.ProvisionDPoPSigner
import eu.europa.ec.eudi.openid4vci.SignFunction
import eu.europa.ec.eudi.openid4vci.SignOperation
import eu.europa.ec.eudi.openid4vci.Signer
import eu.europa.ec.eudi.openid4vci.SubmissionOutcome
import kotlinx.serialization.Serializable
import java.net.URI
import java.security.PrivateKey
import java.security.Signature
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

@Serializable
data class AuthorizeIssuance(
    val credentialIssuer: String,
    val credentialConfigurationId: String,
    val clientId: String,
    val redirectUri: String,
)

@Serializable
data class CompleteIssuance(val sessionId: String, val code: String, val state: String, val iss: String? = null)

@Serializable
data class IssuanceStarted(
    val ok: Boolean,
    val sessionId: String? = null,
    val authorizationUrl: String? = null,
    val error: String? = null,
    val http: List<HttpRecord> = emptyList(),
)

@Serializable
data class IssuanceDone(
    val ok: Boolean,
    val credentialIds: List<String> = emptyList(),
    val credentials: List<String> = emptyList(),
    val error: String? = null,
    val http: List<HttpRecord> = emptyList(),
)

private class IssuanceSession(
    val issuer: Issuer,
    val prepared: AuthorizationRequestPrepared,
    val configurationId: String,
    val recorder: RecordingClient,
)

private val sessions = ConcurrentHashMap<String, IssuanceSession>()

private fun signFunction(privateKey: PrivateKey) = SignFunction { input ->
    Signature.getInstance("SHA256withECDSA").run {
        initSign(privateKey)
        update(input)
        sign()
    }
}

/** Proof signer over the wallet's holder key (the library's own factory is internal). */
private fun holderProofSigner(key: ECKey): BatchSigner<JwtBindingKey> = object : BatchSigner<JwtBindingKey> {
    override val javaAlgorithm = "SHA256withECDSA"
    override suspend fun authenticate() = BatchSignOperation(
        listOf(SignOperation(signFunction(key.toECPrivateKey()), JwtBindingKey.Jwk(key.toPublicJWK()))),
    )
    override suspend fun release(signOps: BatchSignOperation<JwtBindingKey>?) {}
}

/** A fresh P-256 key per session for DPoP proofs. */
private fun dpopProvisioner(): ProvisionDPoPSigner {
    val key = ECKeyGenerator(Curve.P_256).generate()
    val signer = object : Signer<JWK> {
        override val javaAlgorithm = "SHA256withECDSA"
        override suspend fun acquire() = SignOperation(signFunction(key.toECPrivateKey()), key.toPublicJWK() as JWK)
        override suspend fun release(signOperation: SignOperation<JWK>?) {}
    }
    return object : ProvisionDPoPSigner {
        override val popAlgorithm = JwsAlgorithm(JWSAlgorithm.ES256.name)
        override suspend fun invoke(authorizationServer: HttpsUrl): Signer<JWK> = signer
    }
}

private fun vciConfig(clientId: String, redirectUri: String) = OpenId4VCIConfig(
    clientId = clientId,
    authFlowRedirectionURI = URI(redirectUri),
    encryptionSupportConfig = EncryptionSupportConfig(Curve.P_256, 2048, CredentialResponseEncryptionPolicy.SUPPORTED),
    dPoPUsage = DPoPUsage.IfSupported(DPoPConfig(dpopProvisioner())),
    parUsage = ParUsage.IfSupported(),
    proofs = ProofsConfig(
        isNoProofSupported = false,
        jwtProofWithKeyAttestation = null,
        attestationProof = null,
        jwtProofsWithoutKeyAttestation = ProofsConfig.SupportedJwtProof(setOf(JWSAlgorithm.ES256)),
    ),
)

internal suspend fun startIssuance(req: AuthorizeIssuance): IssuanceStarted {
    val rec = RecordingClient()
    return runCatching {
        val issuerId = CredentialIssuerId(req.credentialIssuer).getOrThrow()
        val issuer = Issuer.makeWalletInitiated(
            vciConfig(req.clientId, req.redirectUri), issuerId,
            listOf(CredentialConfigurationIdentifier(req.credentialConfigurationId)), rec.client,
        ).getOrThrow().first
        val prepared = issuer.prepareAuthorizationRequest().getOrThrow()
        val id = UUID.randomUUID().toString()
        sessions[id] = IssuanceSession(issuer, prepared, req.credentialConfigurationId, rec)
        IssuanceStarted(true, id, prepared.authorizationCodeURL.value.toString(), http = rec.records)
    }.getOrElse {
        rec.client.close()
        IssuanceStarted(false, error = "${it::class.simpleName}: ${it.message}", http = rec.records)
    }
}

internal suspend fun completeIssuance(wallet: WalletState, req: CompleteIssuance): IssuanceDone {
    val session = sessions.remove(req.sessionId) ?: return IssuanceDone(false, error = "unknown sessionId")
    val key = wallet.key ?: return IssuanceDone(false, error = "wallet has no holder key")
    val rec = session.recorder
    return try {
        with(session.issuer) {
            val authorized = session.prepared
                .authorizeWithAuthorizationCode(AuthorizationCode(req.code), req.state, issuer = req.iss)
                .getOrThrow()
            val (_, outcome) = authorized.request(
                IssuanceRequestPayload.ConfigurationBased(CredentialConfigurationIdentifier(session.configurationId)),
                ProofSpecification.JwtProofsWithoutKeyAttestation(holderProofSigner(key)),
            ).getOrThrow()
            when (outcome) {
                is SubmissionOutcome.Success -> {
                    val raws = outcome.credentials.map { it.credential.toString() }
                    val ids = raws.map { raw -> UUID.randomUUID().toString().also { wallet.credentials[it] = raw } }
                    IssuanceDone(true, ids, raws, http = rec.records)
                }
                is SubmissionOutcome.Deferred -> IssuanceDone(false, error = "issuer deferred the credential", http = rec.records)
                is SubmissionOutcome.Failed -> IssuanceDone(false, error = outcome.error.toString(), http = rec.records)
            }
        }
    } catch (e: Throwable) {
        IssuanceDone(false, error = "${e::class.simpleName}: ${e.message}", http = rec.records)
    } finally {
        rec.client.close()
    }
}
