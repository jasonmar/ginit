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

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential
import com.google.api.client.googleapis.util.Utils
import com.google.api.services.cloudkms.v1.CloudKMS
import com.google.crypto.tink.integration.gcpkms.GcpKmsAead
import com.google.crypto.tink.proto.KeyTemplate
import com.google.crypto.tink.{Aead, JsonKeysetReader, JsonKeysetWriter, KeysetHandle}

object GcpKms {
  def apply(): GcpKms = {
    val cred = GoogleCredential.getApplicationDefault
    val cloudKms = new CloudKMS.Builder(Utils.getDefaultTransport, Utils.getDefaultJsonFactory, cred)
      .setApplicationName("ginit-0.1")
      .build()
    new GcpKms(cloudKms)
  }
}

class GcpKms(kms: CloudKMS) {
  val id: String = "gcp-kms"

  def generateNew(cryptoKeyUri: String, keyTemplate: KeyTemplate): (KeysetHandle, String) = {
    val keysetHandle = KeysetHandle.generateNew(keyTemplate)
    val masterKey: Aead = new GcpKmsAead(kms, cryptoKeyUri)
    val os = new ByteArrayOutputStream()
    val writer = JsonKeysetWriter.withOutputStream(os)
    keysetHandle.write(writer, masterKey)
    val json = Util.utf8(os.toByteArray)
    (keysetHandle, json)
  }

  def read(json: String, cryptoKeyUri: String): KeysetHandle = {
    val masterKey: Aead = new GcpKmsAead(kms, cryptoKeyUri)
    val reader = JsonKeysetReader.withString(json)
    KeysetHandle.read(reader, masterKey)
  }
}
