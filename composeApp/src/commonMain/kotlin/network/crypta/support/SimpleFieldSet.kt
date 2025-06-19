package network.crypta.support

import kotlin.collections.ArrayDeque

/**
 * A simplified implementation of Freenet's ``SimpleFieldSet`` written in
 * Kotlin common. It stores key/value pairs in a tree where keys are
 * separated by [MULTI_LEVEL_CHAR]. Multiple values for the same key can be
 * appended using [MULTI_VALUE_CHAR].
 */
class SimpleFieldSet(
    private val alwaysUseBase64: Boolean = false
) {
    private val values = mutableMapOf<String, String>()
    private var subsets: MutableMap<String, SimpleFieldSet>? = null
    var endMarker: String? = null
    var header: Array<String>? = null

    companion object {
        const val MULTI_LEVEL_CHAR = '.'
        const val MULTI_VALUE_CHAR = ';'
        const val KEYVALUE_SEPARATOR_CHAR = '='

        fun split(string: String?): Array<String> {
            if (string == null) return emptyArray()
            if (string.isEmpty()) return arrayOf("")

            val parts = mutableListOf<String>()
            var start = 0
            for (i in string.indices) {
                if (string[i] == MULTI_VALUE_CHAR) {
                    parts.add(string.substring(start, i))
                    start = i + 1
                }
            }
            parts.add(string.substring(start))
            return parts.toTypedArray()
        }
    }

    constructor(other: SimpleFieldSet) : this(other.alwaysUseBase64) {
        values.putAll(other.values)
        other.subsets?.let { from ->
            subsets = mutableMapOf()
            for ((k, v) in from) subsets!![k] = SimpleFieldSet(v)
        }
        endMarker = other.endMarker
        header = other.header
    }

    constructor(content: String, allowMultiple: Boolean, allowBase64: Boolean) :
        this() {
        readLines(content.lines(), allowMultiple, allowBase64)
    }

    constructor(lines: List<String>, allowMultiple: Boolean, allowBase64: Boolean) :
        this() {
        readLines(lines, allowMultiple, allowBase64)
    }

    private fun readLines(lines: List<String>, allowMultiple: Boolean, allowBase64: Boolean) {
        var first = true
        var headerMode = true
        val headers = mutableListOf<String>()
        for (line in lines) {
            if (line.isEmpty()) continue
            val ch = line[0]
            if (ch == '#') {
                if (headerMode) headers.add(line.substring(1).trim())
                continue
            }
            if (headerMode) {
                if (headers.isNotEmpty()) header = headers.toTypedArray()
                headerMode = false
            }
            val idx = line.indexOf(KEYVALUE_SEPARATOR_CHAR)
            if (idx >= 0) {
                var key = line.substring(0, idx).trim()
                var value = line.substring(idx + 1)
                if (value.isNotEmpty() && value[0] == KEYVALUE_SEPARATOR_CHAR && allowBase64) {
                    value = value.substring(1).replace("\\s".toRegex(), "").decodeUTF8Base64()
                }
                putInternal(key, value, allowMultiple, overwrite = false)
            } else {
                endMarker = line
                break
            }
            first = false
        }
        if (first) throw IllegalArgumentException("Empty input")
    }

    fun subset(key: String): SimpleFieldSet? {
        val idx = key.indexOf(MULTI_LEVEL_CHAR)
        if (idx == -1) return subsets?.get(key)
        val before = key.substring(0, idx)
        val after = key.substring(idx + 1)
        return subsets?.get(before)?.subset(after)
    }

    fun get(key: String): String? {
        val idx = key.indexOf(MULTI_LEVEL_CHAR)
        return if (idx == -1) {
            values[key]
        } else {
            val before = key.substring(0, idx)
            val after = key.substring(idx + 1)
            subsets?.get(before)?.get(after)
        }
    }

    fun getAll(key: String): Array<String>? = get(key)?.let { split(it) }

    fun putSingle(key: String, value: String?) {
        if (value == null) return
        if (!putInternal(key, value, allowMultiple = false, overwrite = false)) {
            throw IllegalStateException("Value already exists for $key")
        }
    }

    fun putAppend(key: String, value: String?) {
        if (value == null) return
        putInternal(key, value, allowMultiple = true, overwrite = false)
    }

    fun putOverwrite(key: String, value: String?) {
        if (value == null) return
        putInternal(key, value, allowMultiple = false, overwrite = true)
    }


    private fun putInternal(key: String, value: String, allowMultiple: Boolean, overwrite: Boolean): Boolean {
        val idx = key.indexOf(MULTI_LEVEL_CHAR)
        if (idx == -1) {
            val existing = values[key]
            return when {
                existing == null -> {
                    values[key] = value
                    true
                }
                overwrite -> {
                    values[key] = value
                    true
                }
                allowMultiple -> {
                    values[key] = existing + MULTI_VALUE_CHAR + value
                    true
                }
                else -> false
            }
        } else {
            val before = key.substring(0, idx)
            val after = key.substring(idx + 1)
            val sub = subsets?.get(before) ?: SimpleFieldSet(alwaysUseBase64).also {
                if (subsets == null) subsets = mutableMapOf()
                subsets!![before] = it
            }
            return sub.putInternal(after, value, allowMultiple, overwrite)
        }
    }

    fun put(key: String, fs: SimpleFieldSet) {
        require(!fs.isEmpty()) { "Empty" }
        if (subsets == null) subsets = mutableMapOf()
        if (subsets!!.containsKey(key)) throw IllegalArgumentException("Already contains $key")
        subsets!![key] = fs
    }

    fun tput(key: String, fs: SimpleFieldSet?) {
        if (fs == null || fs.isEmpty()) return
        put(key, fs)
    }

    fun put(key: String, value: Int) = putSingle(key, value.toString())
    fun put(key: String, value: Long) = putSingle(key, value.toString())
    fun put(key: String, value: Short) = putSingle(key, value.toString())
    fun put(key: String, value: Double) = putSingle(key, value.toString())
    fun put(key: String, value: Char) = putSingle(key, value.toString())
    fun put(key: String, value: Boolean) = putSingle(key, DataUtil.boolToString(value))

    fun getInt(key: String): Int = get(key)?.toInt() ?: throw FSParseException("No key $key")
    fun getInt(key: String, def: Int): Int = get(key)?.toIntOrNull() ?: def
    fun getLong(key: String): Long = get(key)?.toLong() ?: throw FSParseException("No key $key")
    fun getLong(key: String, def: Long): Long = get(key)?.toLongOrNull() ?: def
    fun getShort(key: String): Short = get(key)?.toShort() ?: throw FSParseException("No key $key")
    fun getShort(key: String, def: Short): Short = get(key)?.toShortOrNull() ?: def
    fun getDouble(key: String): Double = get(key)?.toDouble() ?: throw FSParseException("No key $key")
    fun getDouble(key: String, def: Double): Double = get(key)?.toDoubleOrNull() ?: def
    fun getChar(key: String): Char {
        val v = get(key) ?: throw FSParseException("No key $key")
        if (v.length != 1) throw FSParseException("Cannot parse $v for char $key")
        return v[0]
    }
    fun getChar(key: String, def: Char): Char {
        val v = get(key) ?: return def
        return if (v.length == 1) v[0] else def
    }
    fun getBoolean(key: String, def: Boolean): Boolean = DataUtil.stringToBool(get(key), def)
    fun getBoolean(key: String): Boolean = DataUtil.stringToBool(get(key))

    fun getIntArray(key: String): IntArray? = getAll(key)?.map { it.toInt() }.orEmpty().toIntArray().let { if (it.isEmpty()) null else it }
    fun getDoubleArray(key: String): DoubleArray? = getAll(key)?.map { it.toDouble() }.orEmpty().toDoubleArray().let { if (it.isEmpty()) null else it }

    fun putAllOverwrite(fs: SimpleFieldSet) {
        for ((k, v) in fs.values) values[k] = v
        fs.subsets?.let { from ->
            if (subsets == null) subsets = mutableMapOf()
            for ((k, sub) in from) {
                val mine = subsets!![k]
                if (mine != null) mine.putAllOverwrite(sub) else subsets!![k] = SimpleFieldSet(sub)
            }
        }
    }

    fun removeValue(key: String) {
        val idx = key.indexOf(MULTI_LEVEL_CHAR)
        if (idx == -1) {
            values.remove(key)
            return
        }
        val before = key.substring(0, idx)
        val after = key.substring(idx + 1)
        subsets?.get(before)?.removeValue(after)
    }

    fun removeSubset(key: String) {
        val idx = key.indexOf(MULTI_LEVEL_CHAR)
        if (idx == -1) {
            subsets?.remove(key)
            if (subsets?.isEmpty() == true) subsets = null
            return
        }
        val before = key.substring(0, idx)
        val after = key.substring(idx + 1)
        val sub = subsets?.get(before) ?: return
        sub.removeSubset(after)
        if (sub.isEmpty()) {
            subsets?.remove(before)
            if (subsets?.isEmpty() == true) subsets = null
        }
    }

    fun isEmpty(): Boolean = values.isEmpty() && (subsets == null || subsets!!.isEmpty())

    fun keyIterator(prefix: String = ""): Iterator<String> = KeyIterator(prefix)
    fun toplevelKeyIterator(): Iterator<String> = values.keys.iterator()
    fun directSubsetNameIterator(): Iterator<String>? = subsets?.keys?.iterator()

    fun directSubsets(): Map<String, SimpleFieldSet> = subsets?.toMap() ?: emptyMap()

    inner class KeyIterator(private val prefix: String) : Iterator<String> {
        private val valueKeys = ArrayDeque(values.keys)
        private val subsetKeys = ArrayDeque(subsets?.keys ?: emptySet())
        private var current: Iterator<String>? = null

        override fun hasNext(): Boolean {
            if (valueKeys.isNotEmpty()) return true
            if (current?.hasNext() == true) return true
            while (subsetKeys.isNotEmpty()) {
                val key = subsetKeys.removeFirst()
                val sub = subsets!![key] ?: continue
                current = sub.keyIterator(prefix + key + MULTI_LEVEL_CHAR)
                if (current!!.hasNext()) return true
            }
            return false
        }

        override fun next(): String {
            if (!hasNext()) throw NoSuchElementException()
            if (valueKeys.isNotEmpty()) return prefix + valueKeys.removeFirst()
            return current!!.next()
        }
    }

    fun writeTo(out: Appendable, prefix: String = "", noEndMarker: Boolean = false, useBase64: Boolean = false) {
        header?.forEach { out.append("# ").append(it).append('\n') }
        for ((k, v) in values) writeValue(out, k, v, prefix, useBase64)
        subsets?.forEach { (name, fs) -> fs.writeTo(out, prefix + name + MULTI_LEVEL_CHAR, true, useBase64) }
        if (!noEndMarker) out.append((endMarker ?: "End")).append('\n')
    }

    private fun writeValue(out: Appendable, key: String, value: String, prefix: String, useBase64: Boolean) {
        out.append(prefix).append(key).append(KEYVALUE_SEPARATOR_CHAR)
        if ((useBase64 || alwaysUseBase64) && shouldBase64(value)) {
            out.append(KEYVALUE_SEPARATOR_CHAR)
            out.append(value.encodeUTF8Base64())
        } else {
            out.append(value)
        }
        out.append('\n')
    }

    private fun shouldBase64(value: String): Boolean {
        for (c in value) {
            if (c == KEYVALUE_SEPARATOR_CHAR || c == MULTI_LEVEL_CHAR || c == MULTI_VALUE_CHAR || c.isWhitespace() || c.isISOControl()) return true
        }
        return false
    }

    fun toOrderedString(): String {
        val sb = StringBuilder()
        writeToOrdered(sb)
        return sb.toString()
    }

    fun toOrderedStringWithBase64(): String {
        val sb = StringBuilder()
        writeToOrdered(sb, allowOptionalBase64 = true)
        return sb.toString()
    }

    fun writeToOrdered(out: Appendable, prefix: String = "", noEndMarker: Boolean = false, allowOptionalBase64: Boolean = false) {
        header?.forEach { out.append("# ").append(it).append('\n') }
        val ordered = values.keys.toMutableList().sorted()
        for (k in ordered) writeValue(out, k, values[k]!!, prefix, allowOptionalBase64)
        subsets?.let { map ->
            val subNames = map.keys.toMutableList().sorted()
            for (name in subNames) map[name]!!.writeToOrdered(out, prefix + name + MULTI_LEVEL_CHAR, true, allowOptionalBase64)
        }
        if (!noEndMarker) out.append((endMarker ?: "End")).append('\n')
    }
}

class FSParseException(msg: String) : Exception(msg)
