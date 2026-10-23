package dev.hermeskotlin.core.gateway

import dev.hermeskotlin.core.network.HermesJson
import dev.hermeskotlin.core.storage.KeyValueStore
import io.ktor.client.plugins.api.createClientPlugin
import io.ktor.http.HttpHeaders
import io.ktor.http.isSecure
import io.ktor.util.encodeBase64
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer

/** The username and password a reverse proxy in front of Hermes asks for with HTTP basic auth. */
@Serializable
data class ProxyLogin(val username: String, val password: String) {

    /** The `Authorization` value: `username:password` in UTF-8 and base64 (RFC 7617). */
    val authorization: String get() = "Basic " + "$username:$password".encodeBase64()

    override fun toString(): String = "ProxyLogin(username=$username)"
}

/**
 * The proxy logins for gateways behind HTTP basic auth, by host, kept in the encrypted [KeyValueStore].
 * The proxy protects a hostname, so a login goes with every request to that host and to no other.
 */
class ProxyLogins(private val store: KeyValueStore) {

    private val mutex = Mutex()
    private var cache: Map<String, ProxyLogin>? = null

    suspend fun get(host: String): ProxyLogin? = mutex.withLock { load()[accessHostKey(host)] }

    /** A null [login] forgets the host's login. */
    suspend fun set(host: String, login: ProxyLogin?) = edit { logins ->
        if (login == null) logins - accessHostKey(host) else logins + (accessHostKey(host) to login)
    }

    /** Forgets the logins of every host not in [hosts], e.g. one tested but never signed in to. */
    suspend fun retainOnly(hosts: Collection<String>) {
        val keep = hosts.mapTo(HashSet(), ::accessHostKey)
        edit { logins -> logins.filterKeys { it in keep } }
    }

    private suspend fun edit(transform: (Map<String, ProxyLogin>) -> Map<String, ProxyLogin>) = mutex.withLock {
        val logins = load()
        val next = transform(logins)
        if (next == logins) return@withLock
        if (next.isEmpty()) store.remove(KEY) else store.put(KEY, HermesJson.encodeToString(SERIALIZER, next))
        cache = next
    }

    private suspend fun load(): Map<String, ProxyLogin> = cache
        ?: (store.get(KEY)?.let { runCatching { HermesJson.decodeFromString(SERIALIZER, it) }.getOrNull() } ?: emptyMap())
            .also { cache = it }

    private companion object {
        const val KEY = "proxy_logins.v1"
        val SERIALIZER = MapSerializer(String.serializer(), ProxyLogin.serializer())
    }
}

/**
 * Sends the host's proxy login as `Authorization: Basic` on every gateway request, the `/api/ws` upgrade
 * included. Only over https/wss: basic auth is the password itself, readable to anyone on the way otherwise.
 */
fun proxyBasicAuth(logins: ProxyLogins) = createClientPlugin("ProxyBasicAuth") {
    onRequest { request, _ ->
        if (!request.url.protocol.isSecure()) return@onRequest
        val login = logins.get(request.url.host) ?: return@onRequest
        request.headers[HttpHeaders.Authorization] = login.authorization
    }
}

/** A 401 with a `Basic` challenge: a proxy asking for its login. Hermes's own 401s don't ask for basic auth. */
fun isBasicAuthChallenge(status: Int, challenges: List<String>?): Boolean =
    status == 401 && challenges.orEmpty().any { it.trimStart().startsWith("Basic", ignoreCase = true) }
