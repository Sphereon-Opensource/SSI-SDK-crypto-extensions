package com.sphereon.musap.serializers

import fi.methics.musap.sdk.internal.datatype.KeyAlgorithm
import fi.methics.musap.sdk.internal.datatype.KeyAlgorithm.ECC_ED25519
import fi.methics.musap.sdk.internal.datatype.KeyAlgorithm.ECC_P256_K1
import fi.methics.musap.sdk.internal.datatype.KeyAlgorithm.ECC_P256_R1
import fi.methics.musap.sdk.internal.datatype.KeyAlgorithm.ECC_P384_K1
import fi.methics.musap.sdk.internal.datatype.KeyAlgorithm.ECC_P384_R1
import fi.methics.musap.sdk.internal.datatype.KeyAlgorithm.RSA_2K
import fi.methics.musap.sdk.internal.datatype.KeyAlgorithm.RSA_4K

fun KeyAlgorithm.toEnumString(): String {
    return when {
        this == ECC_ED25519 -> "ecc_ed25519"
        this == ECC_P256_K1 -> "eccp256k1"
        this == ECC_P256_R1 -> "eccp256r1"
        this == ECC_P384_K1 -> "eccp384k1"
        this == ECC_P384_R1 -> "eccp384r1"
        this == RSA_2K -> "rsa2k"
        this == RSA_4K -> "rsa4k"
        else -> throw IllegalStateException("Unknown KeyAlgorithm")
    }
}


fun String.toKeyAlgorithm(): KeyAlgorithm {
    return KeyAlgorithm.fromString(this)
}
