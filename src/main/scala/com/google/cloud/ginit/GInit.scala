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


import java.io.FileWriter
import java.nio.file.Paths

import com.google.auth.oauth2.GInitUtil
import com.google.cloud.ginit.Config.{Kms, Krb}
import com.google.cloud.storage.StorageOptions
import com.google.common.base.Charsets
import org.apache.hadoop.conf.Configuration

object GInit {
  def main(args: Array[String]): Unit = {
    Config.parse(args) match {
      case Some(c) =>
        run(c)
      case _ =>
    }
  }

  def run(c: Config): Unit = {
    EncryptedStorage.init()

    val encryptedStorage: EncryptedStorage = {
      val storage = StorageOptions.newBuilder()
        .setCredentials(GInitUtil.getCredentialsProvider(readWrite = true).getCredentials)
        .build().getService
      new EncryptedStorage(GcpKms(), storage)
    }

    val json = GInitUtil.readJSONCredentials(scopes = GInitUtil.scopes(readWrite = !c.readOnly, readOnly = c.readOnly))
    val keyFile = GInitUtil.convertJson(json)

    val kf = if (c.refreshToken) {
      keyFile
    } else {
      val credentials = GInitUtil.createCredentialsFromPb(keyFile)
      val token = credentials.refreshAccessToken()
      Util.createKeyFile(token)
    }

    val hash = Util.hashKeyFile(kf)

    val conf: Configuration = c.mode match {
      case Kms =>
        EncryptedStorageAccessTokenProvider
          .buildConf(s"gs://${c.tokenBucket}/$hash")
      case Krb =>
        val aead = KrbUtil.aeadFromKeyTab(c.keyTabPath, c.principal)
        val keyFileCipherText = aead.encrypt(kf.toByteArray, c.principal.getBytes(Charsets.UTF_8))
        KrbAccessTokenProvider.buildConf(keyFileCipherText, c.principal, c.remoteKeyTabPath)
    }

    System.out.println("Writing Hadoop Configuration XML to " + Paths.get(c.confFile).toAbsolutePath.toString)
    conf.writeXml(new FileWriter(c.confFile))

    c.mode match {
      case Kms =>
        // Write the keyfile to GCS
        encryptedStorage.put(c.tokenBucket, hash, Util.byteChannel(kf.toByteArray), c.kmsKeyId)
      case Krb =>
        // In Krb mode the keyfile is in Configuration
    }
  }
}
