package dev.hermeskotlin.ui.connect

import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.hermeskotlin.core.gateway.AccessToken
import dev.hermeskotlin.core.gateway.AccessTokens
import dev.hermeskotlin.core.gateway.ClientCertAliases
import dev.hermeskotlin.core.gateway.GatewayProbe
import dev.hermeskotlin.core.gateway.GatewayRepository
import dev.hermeskotlin.core.gateway.GatewayUrl
import dev.hermeskotlin.core.gateway.InvalidGatewayUrlException
import dev.hermeskotlin.core.gateway.ProbeResult
import dev.hermeskotlin.core.gateway.ProxyLogin
import dev.hermeskotlin.core.gateway.ProxyLogins
import dev.hermeskotlin.core.gateway.clientCertAliasFor
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class ConnectUiState(
    val testing: Boolean = false,
    /** Why the address isn't one; the screen words it. */
    val urlError: InvalidGatewayUrlException? = null,
    val accessError: AccessTokenProblem? = null,
    val proxyError: String? = null,
    val result: ProbeResult? = null,
)

/** What's wrong with the service token typed. */
enum class AccessTokenProblem {
    /** One of the Client ID and the Client Secret is filled in, the other blank. */
    HalfFilled,
}

class ConnectViewModel(
    private val probe: GatewayProbe,
    private val access: AccessTokens,
    private val proxyLogins: ProxyLogins,
    private val certs: ClientCertAliases,
    private val gateways: GatewayRepository,
) : ViewModel() {

    val url = TextFieldState()

    /** A Cloudflare Access service token, for a gateway behind Access. Both blank: keep the one saved for the host. */
    val accessClientId = TextFieldState()
    val accessClientSecret = TextFieldState()

    /** The login for a proxy that asks for HTTP basic auth. Both blank: keep the one saved for the host. */
    val proxyUsername = TextFieldState()
    val proxyPassword = TextFieldState()

    private val _state = MutableStateFlow(ConnectUiState())
    val state: StateFlow<ConnectUiState> = _state.asStateFlow()

    private val _accessSaved = MutableStateFlow(false)

    /** Whether a service token is saved for the address typed, so blank fields keep using it. */
    val accessSaved: StateFlow<Boolean> = _accessSaved.asStateFlow()

    private val _certAlias = MutableStateFlow<String?>(null)

    /** The client certificate picked for the address typed, shown by its system-store alias. */
    val certAlias: StateFlow<String?> = _certAlias.asStateFlow()

    private val _proxySaved = MutableStateFlow(false)

    /** Whether a proxy login is saved for the address typed, so blank fields keep using it. */
    val proxySaved: StateFlow<Boolean> = _proxySaved.asStateFlow()

    private var probeJob: Job? = null
    private var lookupJob: Job? = null
    private var proxyLookupJob: Job? = null

    /** The last certificate pick being stored; the probe waits for it so it presents what was just picked. */
    private var certJob: Job? = null

    fun forgetAccessToken() {
        val host = GatewayUrl.parseOrNull(url.text.toString())?.host ?: return
        lookupJob?.cancel()
        lookupJob = viewModelScope.launch {
            access.set(host, null)
            _accessSaved.value = false
        }
    }

    /** Remembers the picked certificate for the address typed, so the probe, the sign-in and the chat present it. */
    fun pickClientCert(alias: String) = setClientCert(alias)

    /** Goes back to presenting no certificate to the address typed. */
    fun clearClientCert() = setClientCert(null)

    /**
     * A saved address takes the pick on its saved gateway, which the sign-in then keeps; only an address not
     * saved yet holds it as a pending pick until the sign-in saves it. A pending pick for a saved gateway would
     * shadow its own, and clearing one would leave the saved certificate in place.
     */
    private fun setClientCert(alias: String?) {
        val gatewayUrl = GatewayUrl.parseOrNull(url.text.toString())
        _certAlias.value = alias.takeIf { gatewayUrl != null }
        if (gatewayUrl == null) return
        val previous = certJob
        certJob = viewModelScope.launch {
            previous?.join()
            if (gateways.all().find(gatewayUrl.value) != null) {
                gateways.setClientCert(gatewayUrl.value, alias)
                certs.set(gatewayUrl.host, null)
            } else {
                certs.set(gatewayUrl.host, alias)
            }
        }
    }

    fun forgetProxyLogin() {
        val host = GatewayUrl.parseOrNull(url.text.toString())?.host ?: return
        proxyLookupJob?.cancel()
        proxyLookupJob = viewModelScope.launch {
            proxyLogins.set(host, null)
            _proxySaved.value = false
        }
    }

    fun testConnection() {
        val gatewayUrl = try {
            GatewayUrl.parse(url.text.toString())
        } catch (e: InvalidGatewayUrlException) {
            _state.value = ConnectUiState(urlError = e)
            return
        }
        val clientId = accessClientId.text.trim().toString()
        val clientSecret = accessClientSecret.text.trim().toString()
        if (clientId.isEmpty() != clientSecret.isEmpty()) {
            _state.value = ConnectUiState(accessError = AccessTokenProblem.HalfFilled)
            return
        }
        // The password as typed: spaces may be part of it.
        val proxyUser = proxyUsername.text.trim().toString()
        val proxyPass = proxyPassword.text.toString()
        if (proxyUser.isEmpty() != proxyPass.isEmpty()) {
            _state.value = ConnectUiState(proxyError = "Enter both the username and the password, or neither.")
            return
        }
        if (':' in proxyUser) {
            _state.value = ConnectUiState(proxyError = "Basic auth can't send a username with a colon in it.")
            return
        }

        probeJob?.cancel()
        _state.value = ConnectUiState(testing = true)
        probeJob = viewModelScope.launch {
            // Saved before the probe, so the probe, the sign-in and the chat all go through Access or the proxy with them.
            if (clientId.isNotEmpty()) {
                lookupJob?.cancel()
                access.set(gatewayUrl.host, AccessToken(clientId, clientSecret))
                _accessSaved.value = true
                accessClientId.clearText()
                accessClientSecret.clearText()
            }
            certJob?.join()
            if (proxyUser.isNotEmpty()) {
                proxyLookupJob?.cancel()
                proxyLogins.set(gatewayUrl.host, ProxyLogin(proxyUser, proxyPass))
                _proxySaved.value = true
                proxyUsername.clearText()
                proxyPassword.clearText()
            }
            val result = probe.probe(gatewayUrl)
            _state.update { it.copy(testing = false, result = result) }
        }
    }

    /** Typing invalidates the previous result, and looks up what the new address already has picked or saved. */
    fun onUrlEdited() {
        val state = _state.value
        if (state.result != null || state.urlError != null || state.accessError != null || state.proxyError != null) {
            probeJob?.cancel()
            _state.value = ConnectUiState()
        }
        val host = GatewayUrl.parseOrNull(url.text.toString())?.host
        lookupJob?.cancel()
        lookupJob = viewModelScope.launch {
            _accessSaved.value = host != null && access.get(host) != null
            // Pending picks first, then the saved gateways: retyping a saved address shows its certificate.
            // A pick made meanwhile is stored first and shows itself, so this never shows the one it replaced.
            val pick = certJob
            pick?.join()
            val alias = host?.let { clientCertAliasFor(it, certs, gateways.all().gateways) }
            if (certJob === pick) _certAlias.value = alias
        }
        proxyLookupJob?.cancel()
        proxyLookupJob = viewModelScope.launch { _proxySaved.value = host != null && proxyLogins.get(host) != null }
    }
}
