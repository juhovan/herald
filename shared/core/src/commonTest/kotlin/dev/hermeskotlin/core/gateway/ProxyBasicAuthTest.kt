package dev.hermeskotlin.core.gateway

import dev.hermeskotlin.core.auth.AuthApi
import dev.hermeskotlin.core.auth.NativeSession
import dev.hermeskotlin.core.auth.NativeTokens
import dev.hermeskotlin.core.auth.PersistentCookiesStorage
import dev.hermeskotlin.core.network.ApiResult
import dev.hermeskotlin.core.network.PROXY_LOGIN_NEEDED
import dev.hermeskotlin.core.network.apiCall
import dev.hermeskotlin.core.network.createHttpClient
import dev.hermeskotlin.core.storage.InMemoryKeyValueStore
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockRequestHandler
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.get
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ProxyBasicAuthTest {

    private val url = GatewayUrl.parse("https://hermes.example.com")
    private val login = ProxyLogin("juho", "pässword:1")
    private val store = InMemoryKeyValueStore()
    private val logins = ProxyLogins(store)
    private val seen = mutableListOf<HttpRequestData>()
    private val json = headersOf(HttpHeaders.ContentType, "application/json")
    private val challenge = headersOf(
        HttpHeaders.WWWAuthenticate to listOf("Basic realm=\"Authorization required\""),
        HttpHeaders.ContentType to listOf("text/html"),
    )

    private fun client(handler: MockRequestHandler) =
        createHttpClient(MockEngine { request -> seen += request; handler(request) }, proxy = logins)

    @Test
    fun loginGoesOnlyToItsOwnHostAsBasicAuth() = runTest {
        logins.set("Hermes.Example.com", login)
        val http = client { respond("{}", HttpStatusCode.OK, json) }

        http.get("https://hermes.example.com/api/status")
        http.get("https://elsewhere.example.com/api/status")

        // "juho:pässword:1" in UTF-8, base64.
        assertEquals("Basic anVobzpww6Rzc3dvcmQ6MQ==", seen[0].headers[HttpHeaders.Authorization])
        assertNull(seen[1].headers[HttpHeaders.Authorization])
    }

    @Test
    fun loginIsNeverSentInPlainText() = runTest {
        logins.set("hermes.example.com", login)
        val http = client { respond("{}", HttpStatusCode.OK, json) }

        http.get("http://hermes.example.com:9119/api/status")

        assertNull(seen.single().headers[HttpHeaders.Authorization])
    }

    @Test
    fun theBrowserSignInsBearerDoesNotReplaceTheProxyLogin() = runTest {
        logins.set(url.host, login)
        val tokens = NativeTokens(store)
        tokens.set(url, NativeSession("AT1", "RT1", 1900000000, provider = "self-hosted"))
        val http = createHttpClient(MockEngine { request -> seen += request; respond("{}", HttpStatusCode.OK, json) }, proxy = logins, bearer = tokens)

        http.get(url.resolve("api/auth/me"))

        assertEquals(login.authorization, seen.single().headers[HttpHeaders.Authorization])
    }

    @Test
    fun retainOnlyForgetsLoginsOfOtherHosts() = runTest {
        logins.set("hermes.example.com", login)
        logins.set("old.example.com", login)

        logins.retainOnly(listOf("HERMES.example.com."))

        assertEquals(login, logins.get("hermes.example.com"))
        assertNull(logins.get("old.example.com"))
    }

    @Test
    fun loginsSurviveARestartAndCanBeForgotten() = runTest {
        logins.set("hermes.example.com", login)
        assertEquals(login, ProxyLogins(store).get("hermes.example.com"))

        logins.set("hermes.example.com", null)
        assertNull(ProxyLogins(store).get("hermes.example.com"))
    }

    @Test
    fun thePasswordStaysOutOfLogs() {
        assertFalse("pässword" in login.toString())
    }

    @Test
    fun aBasicChallengeIsNamedInTheProbe() = runTest {
        val probe = GatewayProbe(client { respond("<html>401</html>", HttpStatusCode.Unauthorized, challenge) })

        val result = assertIs<ProbeResult.ProxyLoginRequired>(probe.probe(url))

        assertFalse(result.loginSent)
        val failed = assertIs<StageResult.Failed>(result.toStageResult())
        assertEquals(CheckNote.Kind.ProxyLoginRequired, failed.problem.kind)
        assertEquals(CheckNote.Kind.FixAddProxyLogin, failed.fix.kind)
    }

    @Test
    fun aChallengeToASentLoginSaysItWasTurnedDown() = runTest {
        logins.set(url.host, login)
        val probe = GatewayProbe(client { respond("<html>401</html>", HttpStatusCode.Unauthorized, challenge) })

        val result = assertIs<ProbeResult.ProxyLoginRequired>(probe.probe(url))

        assertTrue(result.loginSent)
        assertEquals(CheckNote.Kind.ProxyLoginRefused, assertIs<StageResult.Failed>(result.toStageResult()).problem.kind)
    }

    @Test
    fun aChallengeOverPlainHttpAsksForTheHttpsAddress() = runTest {
        val plain = GatewayUrl.parse("http://hermes.example.com")
        val probe = GatewayProbe(client { respond("<html>401</html>", HttpStatusCode.Unauthorized, challenge) })

        val result = assertIs<ProbeResult.ProxyLoginRequired>(probe.probe(plain))

        assertEquals(CheckNote.Kind.FixProxyHttps, assertIs<StageResult.Failed>(result.toStageResult()).fix.kind)
    }

    @Test
    fun apiCallsStoppedByTheProxySaySoInsteadOfSigningOut() = runTest {
        val http = client { respond("<html>401</html>", HttpStatusCode.Unauthorized, challenge) }

        val result = assertIs<ApiResult.Failed>(apiCall { http.get(url.resolve("api/auth/me")) })
        assertEquals(PROXY_LOGIN_NEEDED, result.message)

        val signIn = AuthApi(http, PersistentCookiesStorage(store)).signIn(url, "basic", "user", "pass")
        assertEquals(PROXY_LOGIN_NEEDED, assertIs<ApiResult.Failed>(signIn).message)
    }

    @Test
    fun hermesOwn401IsStillAnExpiredSession() = runTest {
        val http = client { respond("""{"detail":"Not authenticated"}""", HttpStatusCode.Unauthorized, json) }

        assertEquals(ApiResult.SessionExpired, apiCall { http.get(url.resolve("api/auth/me")) })
    }
}
