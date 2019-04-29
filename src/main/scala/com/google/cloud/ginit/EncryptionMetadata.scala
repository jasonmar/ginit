/*
 *    Copyright 2019 Google LLC
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package com.google.cloud.ginit

import com.google.cloud.storage.Blob
import com.google.common.collect.ImmutableMap
import com.google.common.io.BaseEncoding

object EncryptionMetadata {
  val AAD = "aad"
  val KeyId = "keyId"
  val KmsType = "kms"
  val Keyset = "keyset"

  val RequiredKeys: Seq[String] = Seq(AAD, KeyId, KmsType, Keyset)

  def fromBlob(blob: Blob): EncryptionMetadata = {
    val meta = blob.getMetadata
    RequiredKeys.foreach(s => require(meta.containsKey(s), s"metadata missing key $s"))

    val aad: Array[Byte] = BaseEncoding.base64.decode(meta.get(AAD))
    val keyId: String = meta.get(KeyId)
    val kms: String = meta.get(KmsType)
    val keyset: String = meta.get(Keyset)

    require(aad.length == EncryptedStorage.IvLength, s"AAD must be ${EncryptedStorage.IvLength} bytes")

    EncryptionMetadata(aad, keyId, kms, keyset)
  }
}

case class EncryptionMetadata(aad: Array[Byte], keyId: String, kms: String, keyset: String) {
  def asJava: java.util.Map[String,String] = ImmutableMap.of(
    EncryptionMetadata.AAD, BaseEncoding.base64.encode(aad),
    EncryptionMetadata.KmsType, kms,
    EncryptionMetadata.KeyId, keyId,
    EncryptionMetadata.Keyset, keyset
  )
}