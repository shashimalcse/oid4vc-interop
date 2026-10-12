/*
 * A minimal HTTP wallet on the EUDI reference library eudi-lib-jvm-openid4vp-kt, so vcit can
 * drive the same OpenID4VP stack EU wallets use. Test use only: keys live in memory and TLS
 * is not verified (the verifier's request signature is, against the configured anchors).
 *
 *   POST /wallets                                     -> {walletId}
 *   POST /wallets/{id}/keys          {jwk}            -> {keyId}       (private EC P-256)
 *   POST /wallets/{id}/credentials   {raw}            -> {credentialId} (SD-JWT VC)
 *   POST /wallets/{id}/presentations/resolve {requestUrl}  resolve + validate only
 *   POST /wallets/{id}/presentations         {requestUrl}  resolve, build vp_token, send
 *
 * Trust anchors for signed requests (x509_san_dns / x509_hash) are read from
 * $VCIT_TRUST_ANCHORS (a PEM bundle) on every request, so vcit can change them without a restart.
 */
package vcit.eudi

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vp.Consensus
import eu.europa.ec.eudi.openid4vp.DispatchOutcome
import eu.europa.ec.eudi.openid4vp.EncryptionParameters
import eu.europa.ec.eudi.openid4vp.OpenId4VPConfig
import eu.europa.ec.eudi.openid4vp.OpenId4Vp
import eu.europa.ec.eudi.openid4vp.Resolution
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject
import eu.europa.ec.eudi.openid4vp.ResponseEncryptionConfiguration
import eu.europa.ec.eudi.openid4vp.ResponseMode
import eu.europa.ec.eudi.openid4vp.SignedRequestConfiguration
import eu.europa.ec.eudi.openid4vp.SupportedClientIdPrefix
import eu.europa.ec.eudi.openid4vp.SupportedRequestUriMethods
import eu.europa.ec.eudi.openid4vp.VerifiablePresentation
import eu.europa.ec.eudi.openid4vp.VerifiablePresentations
import eu.europa.ec.eudi.openid4vp.VpFormatsSupported
import eu.europa.ec.eudi.openid4vp.X509CertificateTrust
import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.HttpSend
import io.ktor.client.plugins.plugin
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.ByteArrayInputStream
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.time.Clock
import java.util.Date
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation as ServerContentNegotiation

private val json = Json { ignoreUnknownKeys = true; explicitNulls = false }

// -- trust ---------------------------------------------------------------------------------------

private fun trustAnchors(): List<X509Certificate> {
    val path = System.getenv("VCIT_TRUST_ANCHORS") ?: "/vcit/anchors.pem"
    val file = File(path)
    if (!file.exists()) return emptyList()
    val factory = CertificateFactory.getInstance("X.509")
    return factory.generateCertificates(ByteArrayInputStream(file.readBytes())).map { it as X509Certificate }
}

/** Trusted if the chain contains an anchor, or validates (PKIX, no revocation) to one. */
private val x509Trust = X509CertificateTrust { chain ->
    val anchors = trustAnchors()
    if (anchors.isEmpty() || chain.isEmpty()) return@X509CertificateTrust false
    if (chain.any { it in anchors }) return@X509CertificateTrust true
    runCatching {
        val factory = CertificateFactory.getInstance("X.509")
        val params = PKIXParameters(anchors.map { TrustAnchor(it, null) }.toSet()).apply { isRevocationEnabled = false }
        CertPathValidator.getInstance("PKIX").validate(factory.generateCertPath(chain), params)
        true
    }.getOrDefault(false)
}

// -- HTTP client (records the verifier's answer to the authorization response) ---------------------

private object InsecureTls : X509TrustManager {
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
}

@Serializable
data class HttpRecord(val method: String, val url: String, val status: Int, val body: String)

private class RecordingClient {
    val records = mutableListOf<HttpRecord>()
    val client: HttpClient = HttpClient(OkHttp) {
        engine {
            config {
                val ctx = SSLContext.getInstance("TLS").apply { init(null, arrayOf(InsecureTls), SecureRandom()) }
                sslSocketFactory(ctx.socketFactory, InsecureTls)
                hostnameVerifier { _, _ -> true }
            }
        }
        install(ClientContentNegotiation) { json(json) }
        expectSuccess = false
    }.also { c ->
        c.plugin(HttpSend).intercept { request ->
            val call = execute(request)
            val body = runCatching { call.response.bodyAsText() }.getOrDefault("")
            records += HttpRecord(request.method.value, request.url.buildString(), call.response.status.value, body.take(4000))
            call
        }
    }
}

// -- wallet state ----------------------------------------------------------------------------------

private class Wallet {
    var key: ECKey? = null
    val credentials = ConcurrentHashMap<String, String>()
}

private val wallets = ConcurrentHashMap<String, Wallet>()

private val config = OpenId4VPConfig(
    vpFormatsSupported = VpFormatsSupported(VpFormatsSupported.SdJwtVc.HAIP, null),
    signedRequestConfiguration = SignedRequestConfiguration(
        supportedAlgorithms = listOf(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512),
        supportedRequestUriMethods = SupportedRequestUriMethods.Both(SupportedRequestUriMethods.Post()),
    ),
    responseEncryptionConfiguration = ResponseEncryptionConfiguration.Supported(
        supportedAlgorithms = listOf(JWEAlgorithm.ECDH_ES),
        supportedMethods = listOf(EncryptionMethod.A128GCM, EncryptionMethod.A256GCM),
    ),
    supportedClientIdPrefixes = listOf(
        SupportedClientIdPrefix.X509SanDns(x509Trust),
        SupportedClientIdPrefix.X509Hash(x509Trust),
        SupportedClientIdPrefix.RedirectUri,
    ),
    clock = Clock.systemDefaultZone(),
)

// -- API types -------------------------------------------------------------------------------------

@Serializable data class KeyRequest(val jwk: JsonObject)
@Serializable data class CredentialRequest(val raw: String)
@Serializable data class RequestUrl(val requestUrl: String)

@Serializable
data class Resolved(
    val ok: Boolean,
    val clientId: String? = null,
    val responseMode: String? = null,
    val responseUri: String? = null,
    val nonce: String? = null,
    val credentialQueries: List<String> = emptyList(),
    val error: String? = null,
    val http: List<HttpRecord> = emptyList(),
)

@Serializable
data class Presented(
    val ok: Boolean,
    val stage: String,
    val outcome: String? = null,
    val verifierStatus: Int? = null,
    val verifierBody: String? = null,
    val redirectUri: String? = null,
    val error: String? = null,
    val http: List<HttpRecord> = emptyList(),
)

// -- presentation ----------------------------------------------------------------------------------

private fun describe(r: Resolution.Invalid): String = r.error.toString()

private fun responseUri(mode: ResponseMode): String? = when (mode) {
    is ResponseMode.DirectPost -> mode.responseURI.toString()
    is ResponseMode.DirectPostJwt -> mode.responseURI.toString()
    else -> null
}

private fun sha256b64(s: String): String =
    Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.US_ASCII))).toString()

/** The stored credential for a DCQL query: matching vct_values if given, else the first one. */
private fun pick(wallet: Wallet, vctValues: List<String>?): String? =
    wallet.credentials.values.firstOrNull { raw ->
        vctValues.isNullOrEmpty() || run {
            val payload = SignedJWT.parse(raw.substringBefore("~")).jwtClaimsSet
            payload.getStringClaim("vct") in vctValues
        }
    }

/** All disclosures plus a KB-JWT bound to this request (aud = full client_id, nonce, sd_hash). */
private fun presentation(raw: String, key: ECKey, request: ResolvedRequestObject): String {
    val withoutKb = if (raw.endsWith("~")) raw else "$raw~"
    val claims = JWTClaimsSet.Builder()
        .audience(request.client.id.clientId)
        .claim("nonce", request.nonce)
        .issueTime(Date())
        .claim("sd_hash", sha256b64(withoutKb))
        .build()
    val header = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType("kb+jwt")).build()
    val kb = SignedJWT(header, claims).apply { sign(ECDSASigner(key)) }
    return withoutKb + kb.serialize()
}

private suspend fun present(wallet: Wallet, url: String, send: Boolean): Any {
    val rec = RecordingClient()
    rec.client.use { http ->
        val vp = OpenId4Vp.overRedirects(config, http)
        val request = when (val r = vp.resolveRequestUri(url)) {
            is Resolution.Success -> r.requestObject
            is Resolution.Invalid ->
                return if (send) Presented(false, "resolve", error = describe(r), http = rec.records)
                else Resolved(false, error = describe(r), http = rec.records)
        }
        val queries = request.query.credentials.value
        if (!send) {
            return Resolved(
                ok = true,
                clientId = request.client.id.clientId,
                responseMode = request.responseMode::class.simpleName,
                responseUri = responseUri(request.responseMode),
                nonce = request.nonce,
                credentialQueries = queries.map { it.id.value },
                http = rec.records,
            )
        }
        val key = wallet.key ?: return Presented(false, "build", error = "wallet has no holder key", http = rec.records)
        val presentations = queries.associate { q ->
            val vct = (q.meta?.get("vct_values") as? JsonArray)?.map { it.jsonPrimitive.content }
            val raw = pick(wallet, vct)
                ?: return Presented(false, "build", error = "no credential matches query ${q.id.value} (vct $vct)", http = rec.records)
            q.id to listOf(VerifiablePresentation.Generic(presentation(raw, key, request)))
        }
        val before = rec.records.size
        val outcome = runCatching {
            vp.dispatch(
                request,
                Consensus.PositiveConsensus(VerifiablePresentations(presentations)),
                EncryptionParameters.DiffieHellman(Base64URL.encode("vcit")),
            )
        }.getOrElse { return Presented(false, "send", error = it.toString(), http = rec.records) }
        val post = rec.records.drop(before).lastOrNull { it.method == HttpMethod.Post.value }
        return when (outcome) {
            is DispatchOutcome.VerifierResponse.Accepted ->
                Presented(true, "send", "accepted", post?.status, post?.body, outcome.redirectURI?.toString(), http = rec.records)
            is DispatchOutcome.VerifierResponse.Rejected ->
                Presented(false, "send", "rejected", post?.status, post?.body, outcome.redirectURI?.toString(), http = rec.records)
            is DispatchOutcome.RedirectURI ->
                Presented(true, "send", "redirect", redirectUri = outcome.value.toString(), http = rec.records)
        }
    }
}

// -- server ----------------------------------------------------------------------------------------

fun main() {
    val port = System.getenv("PORT")?.toInt() ?: 7007
    embeddedServer(Netty, port = port) {
        install(ServerContentNegotiation) { json(json) }
        routing {
            get("/health") { call.respond(mapOf("status" to "ok", "library" to "eudi-lib-jvm-openid4vp-kt 0.16.2")) }
            post("/wallets") {
                val id = UUID.randomUUID().toString()
                wallets[id] = Wallet()
                call.respond(HttpStatusCode.Created, mapOf("walletId" to id))
            }
            post("/wallets/{id}/keys") {
                val w = wallets[call.parameters["id"]] ?: return@post call.respond(HttpStatusCode.NotFound, mapOf("error" to "no such wallet"))
                val key = ECKey.parse(call.receive<KeyRequest>().jwk.toString())
                require(key.isPrivate) { "a private JWK is required" }
                w.key = key
                call.respond(HttpStatusCode.Created, mapOf("keyId" to (key.keyID ?: "holder")))
            }
            post("/wallets/{id}/credentials") {
                val w = wallets[call.parameters["id"]] ?: return@post call.respond(HttpStatusCode.NotFound, mapOf("error" to "no such wallet"))
                val raw = call.receive<CredentialRequest>().raw
                SignedJWT.parse(raw.substringBefore("~")) // fail early on garbage
                val id = UUID.randomUUID().toString()
                w.credentials[id] = raw
                call.respond(HttpStatusCode.Created, mapOf("credentialId" to id))
            }
            post("/wallets/{id}/presentations/resolve") {
                val w = wallets[call.parameters["id"]] ?: return@post call.respond(HttpStatusCode.NotFound, mapOf("error" to "no such wallet"))
                call.respond(present(w, call.receive<RequestUrl>().requestUrl, send = false) as Resolved)
            }
            post("/wallets/{id}/presentations") {
                val w = wallets[call.parameters["id"]] ?: return@post call.respond(HttpStatusCode.NotFound, mapOf("error" to "no such wallet"))
                call.respond(present(w, call.receive<RequestUrl>().requestUrl, send = true) as Presented)
            }
        }
    }.start(wait = true)
}
