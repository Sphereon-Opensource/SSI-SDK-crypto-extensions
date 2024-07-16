package com.sphereon.musap.serializers

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.WritableMap
import fi.methics.musap.sdk.extension.SscdSettings
import fi.methics.musap.sdk.internal.datatype.KeyAlgorithm
import fi.methics.musap.sdk.internal.datatype.SscdInfo
import fi.methics.musap.sdk.internal.util.MusapSscd


fun SscdInfo.toWritableMap(): WritableMap {

    val supportedAlgorithms = Arguments.createArray()
    this.supportedAlgorithms?.forEach {
        supportedAlgorithms.pushString(it.toEnumString())
    }

    return Arguments.createMap().apply {
        putString("sscdId", sscdId)
        putString("sscdType", sscdType)
        putString("sscdName", sscdName)
        putString("country", country)
        putString("provider", provider)
        putBoolean("isKeyGenSupported", isKeygenSupported ?: false)
        putArray("supportedAlgorithms", supportedAlgorithms)
    }
}

fun SscdSettings.toWritableMap(): WritableMap {

    val settings = Arguments.createMap()
    this.settings.entries.forEach {
        settings.putString(it.key, it.value)
    }
    return settings
}

fun MusapSscd.toWritableMap(): WritableMap {

    return Arguments.createMap().apply {
        putString("sscdId", sscdId)
        putMap("sscdInfo", sscdInfo.toWritableMap())
        putMap("settings", settings.toWritableMap())
    }
}
