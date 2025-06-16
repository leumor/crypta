package network.crypta.support

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NetworkUtilTest {
    @Test
    fun testSiteLocalIPv4() {
        val a = "10.1.2.3"
        val b = "172.16.0.1"
        val c = "192.168.1.1"
        assertTrue(NetworkUtil.isSiteLocalAddress(a))
        assertTrue(NetworkUtil.isSiteLocalAddress(b))
        assertTrue(NetworkUtil.isSiteLocalAddress(c))
    }

    @Test
    fun testSiteLocalIPv6() {
        val a = "fc00::1"
        val b = "fec0::1"
        assertTrue(NetworkUtil.isSiteLocalAddress(a))
        assertTrue(NetworkUtil.isSiteLocalAddress(b))
    }

    @Test
    fun testIsValidAddress_ipv4() {
        val public = "8.8.8.8"
        assertTrue(NetworkUtil.isValidAddress(public, false))

        val zeroFirst = "0.1.2.3"
        assertFalse(NetworkUtil.isValidAddress(zeroFirst, false))

        val loop = "127.0.0.1"
        assertFalse(NetworkUtil.isValidAddress(loop, false))
        assertTrue(NetworkUtil.isValidAddress(loop, true))

        val siteLocal = "192.168.1.1"
        assertFalse(NetworkUtil.isValidAddress(siteLocal, false))
        assertTrue(NetworkUtil.isValidAddress(siteLocal, true))

        val multicast = "224.0.0.1"
        assertFalse(NetworkUtil.isValidAddress(multicast, false))
    }

    @Test
    fun testIsValidAddress_ipv6() {
        val public = "2001:db8::1"
        assertTrue(NetworkUtil.isValidAddress(public, false))

        val loop = "::1"
        assertFalse(NetworkUtil.isValidAddress(loop, false))
        assertTrue(NetworkUtil.isValidAddress(loop, true))

        val linkLocal = "fe80::1"
        assertFalse(NetworkUtil.isValidAddress(linkLocal, false))
        assertTrue(NetworkUtil.isValidAddress(linkLocal, true))

        val siteLocal = "fc00::1"
        assertFalse(NetworkUtil.isValidAddress(siteLocal, false))
        assertTrue(NetworkUtil.isValidAddress(siteLocal, true))

        val multicast = "ff02::1"
        assertFalse(NetworkUtil.isValidAddress(multicast, false))
    }

    @Test
    fun validHostname() {
        assertTrue(NetworkUtil.isValidHostname("example.com", false))
        assertTrue(NetworkUtil.isValidHostname("sub.domain.co", false))
    }

    @Test
    fun invalidHostname() {
        assertFalse(NetworkUtil.isValidHostname("example", false))
        assertFalse(NetworkUtil.isValidHostname("ex@mple.com", false))
    }

    @Test
    fun allowIpAddress_ipv4() {
        val ip = "192.168.1.1"
        assertFalse(NetworkUtil.isValidHostname(ip, false))
        assertTrue(NetworkUtil.isValidHostname(ip, true))
    }

    @Test
    fun allowIpAddress_ipv6() {
        val ip = "2001:db8::1"
        assertFalse(NetworkUtil.isValidHostname(ip, false))
        assertTrue(NetworkUtil.isValidHostname(ip, true))
    }

    @Test
    fun invalidIpAddress() {
        val ip = "256.0.0.1"
        assertFalse(NetworkUtil.isValidHostname(ip, true))
    }
}

