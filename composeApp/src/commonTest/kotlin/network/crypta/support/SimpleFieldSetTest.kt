package network.crypta.support

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith

class SimpleFieldSetTest {
    private val samplePairs = arrayOf(
        "foo" to "bar",
        "foo.bar" to "foobar",
        "foo.bar.foo" to "foobar",
        "foo.bar.boo.far" to "foobar",
        "foo2" to "foobar.fooboo.foofar.foofoo",
        "foo3" to "=${'b'}ar"
    )

    private fun sfsFromSample(): SimpleFieldSet {
        val sfs = SimpleFieldSet()
        for ((k, v) in samplePairs) sfs.putSingle(k, v)
        return sfs
    }

    @Test
    fun putSingleWithPairedDots() {
        val sfs = SimpleFieldSet()
        sfs.putSingle("foo..bar.", "foobar")
        assertEquals("foobar", sfs.get("foo..bar."))
        assertEquals("foobar", sfs.subset("foo")!!.subset("")!!.subset("bar")!!.get(""))
    }

    @Test
    fun putAppendWithPairedDots() {
        val sfs = SimpleFieldSet()
        sfs.putAppend("foo..bar", "foobar")
        assertEquals("foobar", sfs.get("foo..bar"))
    }

    @Test
    fun putAndGetPairs() {
        val pairs = arrayOf(
            "A" to "a",
            "B" to "b",
            "C" to "c"
        )
        val sfs = SimpleFieldSet()
        for ((k,v) in pairs) sfs.putSingle(k,v)
        for ((k,v) in pairs) assertEquals(v, sfs.get(k))
    }

    @Test
    fun subsetRetrieval() {
        val sfs = SimpleFieldSet()
        sfs.putSingle("A.B", "ab")
        assertEquals("ab", sfs.subset("A")!!.get("B"))
    }

    @Test
    fun putAllOverwrite() {
        val orig = sfsFromSample()
        val other = SimpleFieldSet()
        for ((k,v) in samplePairs) other.putSingle(k, "$v-")
        orig.putAllOverwrite(other)
        for ((k,v) in samplePairs) assertEquals("$v-", orig.get(k))
    }

    @Test
    fun putSubset() {
        val sfs = SimpleFieldSet()
        val sub = sfsFromSample()
        sfs.put("prefix", sub)
        for ((k,v) in samplePairs) assertEquals(v, sfs.get("prefix.$k"))
    }

    @Test
    fun tputIgnoresEmpty() {
        val sfs = SimpleFieldSet()
        sfs.tput("a", SimpleFieldSet())
        assertNull(sfs.subset("a"))
    }

    @Test
    fun booleanPutGet() {
        val sfs = SimpleFieldSet()
        sfs.put("a", true)
        assertTrue(sfs.getBoolean("a", false))
    }

    @Test
    fun intLongCharShortDouble() {
        val sfs = SimpleFieldSet()
        sfs.put("i", 1)
        sfs.put("l", 2L)
        sfs.put("c", 'x')
        sfs.put("s", 3.toShort())
        sfs.put("d", 2.0)
        assertEquals(1, sfs.getInt("i"))
        assertEquals(2L, sfs.getLong("l"))
        assertEquals('x', sfs.getChar("c"))
        assertEquals(3.toShort(), sfs.getShort("s"))
        assertEquals(2.0, sfs.getDouble("d"))
    }

    @Test
    fun keyIteration() {
        val sfs = sfsFromSample()
        val keys = sfs.keyIterator().asSequence().toSet()
        assertEquals(samplePairs.size, keys.size)
        for ((k, _) in samplePairs) assertTrue(k in keys)
    }

    @Test
    fun directSubsetsWhenEmpty() {
        val sfs = SimpleFieldSet()
        assertTrue(sfs.directSubsets().isEmpty())
    }

    @Test
    fun base64RoundTrip() {
        val sfs = SimpleFieldSet()
        sfs.putSingle("key", " value")
        val sb = StringBuilder()
        sfs.writeTo(sb, "", false, true)
        val parsed = SimpleFieldSet(sb.lines(), false, true)
        assertEquals(" value", parsed.get("key"))
    }

    @Test
    fun splitUtility() {
        assertContentEquals(arrayOf("blah"), SimpleFieldSet.split("blah"))
        assertContentEquals(arrayOf("blah","1","2"), SimpleFieldSet.split("blah;1;2"))
        assertContentEquals(arrayOf("","blah"), SimpleFieldSet.split(";blah"))
    }
}
