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

import com.google.crypto.tink.KeysetReader
import com.google.crypto.tink.aead.AeadKeyTemplates
import com.google.crypto.tink.proto._
import com.google.protobuf.ByteString
import javax.security.auth.Subject

object KrbKeysetReader {
  val KeyTemplate: KeyTemplate = AeadKeyTemplates.AES128_GCM
  val TypeUrl: String = KeyTemplate.getTypeUrl

  private def newAesGcmKey(keyBytes: Array[Byte]): AesGcmKey =
    AesGcmKey.newBuilder()
      .setKeyValue(ByteString.copyFrom(keyBytes))
      .build()

  private def newKeyData(keyBytes: Array[Byte]): KeyData =
    KeyData.newBuilder()
      .setKeyMaterialType(KeyData.KeyMaterialType.SYMMETRIC)
      .setTypeUrl(KrbKeysetReader.TypeUrl)
      .setValue(newAesGcmKey(keyBytes).toByteString)
      .build()

  private def newKey(keyBytes: Array[Byte]): Keyset.Key =
    Keyset.Key.newBuilder()
      .setKeyData(newKeyData(keyBytes))
      .setStatus(KeyStatusType.ENABLED)
      .setOutputPrefixType(OutputPrefixType.RAW)
      .build()

  def read(keyBytes: Array[Byte]): Keyset =
    Keyset.newBuilder()
      .addKey(newKey(keyBytes))
      .build
}

/** Reads AES128 Private Key from Kerberos KeyTab for a Principal
  * Creates a Keyset used to to create an encryption primitive
  *
  * @param principal
  * @param keyTabPath
  */
class KrbKeysetReader(principal: String, keyTabPath: String) extends KeysetReader {
  override def read(): Keyset = {
    val subject: Subject = KrbUtil.getSubject(principal, keyTabPath)
    KrbUtil.findKerberosKey(subject, principal, "AES128") match {
      case Some(keyBytes) =>
        KrbKeysetReader.read(keyBytes)
      case _ =>
        throw new RuntimeException("unable to read ")
    }
  }

  override def readEncrypted(): EncryptedKeyset =
    throw new NotImplementedError()
}
