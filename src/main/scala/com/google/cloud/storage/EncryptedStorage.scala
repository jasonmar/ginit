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

package com.google.cloud.storage

import java.nio.channels.ReadableByteChannel

import com.google.cloud.ginit.Util
import com.google.crypto.tink.GcpKms
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.proto.KeyTemplate
import com.google.crypto.tink.streamingaead.{StreamingAeadConfig, StreamingAeadFactory, StreamingAeadKeyTemplates}
import com.google.crypto.tink.subtle.Random
import javax.crypto.spec.IvParameterSpec


object EncryptedStorage {
  val KeyTemplate: KeyTemplate = StreamingAeadKeyTemplates.AES256_GCM_HKDF_4KB
  val Algorithm = "AES256_GCM_HKDF_4KB"
  val ContentType = "application/octet-stream"
  val IvLength = 12

  def genIv: IvParameterSpec =
    new IvParameterSpec(Random.randBytes(IvLength))

  def init(): Unit = {
    AeadConfig.register()
    StreamingAeadConfig.register()
  }

  def apply(): EncryptedStorage = {
    val storage = StorageOptions.newBuilder().build().getService
    new EncryptedStorage(GcpKms(), storage)
  }
}

class EncryptedStorage(private val kms: GcpKms, private val storage: Storage) {
  def get(bucket: String, objName: String): ReadableByteChannel = {
    val blob = storage.get(BlobId.of(bucket, objName))
    val meta = EncryptionMetadata.fromBlob(blob)
    val keysetHandle = kms.read(meta.keyset, meta.keyId.stripPrefix("gcp-kms://"))
    StreamingAeadFactory.getPrimitive(keysetHandle)
      .newDecryptingChannel(blob.reader(), meta.aad)
  }

  def put(bucket: String, obj: String, rc: ReadableByteChannel, keyId: String):
  BlobInfo = {
    val (keysetHandle,keysetJson) = kms.generateNew(keyId.stripPrefix("gcp-kms://"), EncryptedStorage.KeyTemplate)

    val meta = EncryptionMetadata(EncryptedStorage.genIv.getIV, keyId, kms.id, keysetJson)

    val blobInfo = BlobInfo.newBuilder(BlobId.of(bucket, obj))
      .setContentType(EncryptedStorage.ContentType)
      .setContentEncoding(EncryptedStorage.Algorithm)
      .setMetadata(meta.asJava)
      .build

    val wc = StreamingAeadFactory.getPrimitive(keysetHandle)
      .newEncryptingChannel(storage.writer(blobInfo), meta.aad)

    Util.transfer(rc, wc)
    blobInfo
  }
}

