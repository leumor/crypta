package network.crypta.network

import network.crypta.support.NetworkUtil

data class HostInfo(val hostName: String, var ipAddress: String?) {
    init {
        require(NetworkUtil.isValidHostname(hostName, true)) {
            "Invalid hostname: $hostName"
        }

        // If hostName is an IP address, set ipAddress to it
        if (NetworkUtil.isValidAddress(hostName, true)) {
            ipAddress = hostName
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as HostInfo

        // host name is different
        if (!hostName.equals(other.hostName, true)) return false

        // host name is the same but IP is different
        if (ipAddress != null && other.ipAddress != null && !ipAddress.equals(
                other.ipAddress,
                true
            )
        ) return false

        return true
    }

    override fun hashCode(): Int {
        return hostName.hashCode()
    }
}