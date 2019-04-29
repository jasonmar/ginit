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

import java.io.ByteArrayOutputStream

import com.google.crypto.tink.proto.KeyTemplate
import com.google.crypto.tink.{Aead, JsonKeysetReader, JsonKeysetWriter, KeysetHandle}

/** Generates a new Secret Key and encrypts with with KMS
  *
  * @param principal
  * @param keyTabPath
  */
class KrbKms(principal: String, keyTabPath: String) {
  val id: String = "gcp-kms"
  private val masterKey: Aead = KrbUtil.aeadFromKeyTab(keyTabPath, principal)

  /** Generates a new Secret Key and JSON representation
    *
    * @param cryptoKeyUri KMS Crypto Key ID
    * @param keyTemplate Tink KeyTemplate
    * @return tuple of keysetHandle for immediate use
    *         and JSON to be stored in blob metadata
    */
  def generateNew(cryptoKeyUri: String, keyTemplate: KeyTemplate): (KeysetHandle, String) = {
    val keysetHandle = KeysetHandle.generateNew(keyTemplate)
    val os = new ByteArrayOutputStream()
    val writer = JsonKeysetWriter.withOutputStream(os)
    keysetHandle.write(writer, masterKey)
    val json = Util.utf8(os.toByteArray)
    (keysetHandle, json)
  }

  def read(json: String, cryptoKeyUri: String): KeysetHandle = {
    val reader = JsonKeysetReader.withString(json)
    KeysetHandle.read(reader, masterKey)
  }
}
