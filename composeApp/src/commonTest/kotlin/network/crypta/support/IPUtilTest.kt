package network.crypta.support

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class IPUtilTest {

    @Test
    fun testSiteLocalIPv4() {
        val a = "10.1.2.3"
        val b = "172.16.0.1"
        val c = "192.168.1.1"
        assertTrue(IPUtil.isSiteLocalAddress(a))
        assertTrue(IPUtil.isSiteLocalAddress(b))
        assertTrue(IPUtil.isSiteLocalAddress(c))
    }

    @Test
    fun testSiteLocalIPv6() {
        val a = "fc00::1"
        val b = "fec0::1"
        assertTrue(IPUtil.isSiteLocalAddress(a))
        assertTrue(IPUtil.isSiteLocalAddress(b))
    }

    @Test
    fun testIsValidAddress_ipv4() {
        val public = "8.8.8.8"
        assertTrue(IPUtil.isValidAddress(public, false))

        val zeroFirst = "0.1.2.3"
        assertFalse(IPUtil.isValidAddress(zeroFirst, false))

        val loop = "127.0.0.1"
        assertFalse(IPUtil.isValidAddress(loop, false))
        assertTrue(IPUtil.isValidAddress(loop, true))

        val siteLocal = "192.168.1.1"
        assertFalse(IPUtil.isValidAddress(siteLocal, false))
        assertTrue(IPUtil.isValidAddress(siteLocal, true))

        val multicast = "224.0.0.1"
        assertFalse(IPUtil.isValidAddress(multicast, false))
    }

    @Test
    fun testIsValidAddress_ipv6() {
        val public = "2001:db8::1"
        assertTrue(IPUtil.isValidAddress(public, false))

        val loop = "::1"
        assertFalse(IPUtil.isValidAddress(loop, false))
        assertTrue(IPUtil.isValidAddress(loop, true))

        val linkLocal = "fe80::1"
        assertFalse(IPUtil.isValidAddress(linkLocal, false))
        assertTrue(IPUtil.isValidAddress(linkLocal, true))

        val siteLocal = "fc00::1"
        assertFalse(IPUtil.isValidAddress(siteLocal, false))
        assertTrue(IPUtil.isValidAddress(siteLocal, true))

        val multicast = "ff02::1"
        assertFalse(IPUtil.isValidAddress(multicast, false))
    }
}
