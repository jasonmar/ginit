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


import com.google.cloud.hadoop.util.AccessTokenProvider
import com.google.cloud.storage.BlobId
import com.google.common.collect.ImmutableList
import org.apache.hadoop.conf.Configuration

object EncryptedStorageAccessTokenProvider {
  val ClassName: String = "com.google.cloud.ginit.EncryptedStorageAccessTokenProvider"
  val GInitAccessTokenUri = "fs.gs.auth.access.token.uri"
  val CloudKMSScope: ImmutableList[String] = ImmutableList.of("https://www.googleapis.com/auth/cloudkms")

  def buildConf(accessTokenUri: String): Configuration = {
    val conf = new Configuration(false)
    conf.set(EncryptedStorageAccessTokenProvider.GInitAccessTokenUri, accessTokenUri)
    conf.set(AccessTokenProviderUtil.AccessTokenProviderImpl,
      ClassName)
    conf
  }
}

class EncryptedStorageAccessTokenProvider extends AccessTokenProvider {
  import EncryptedStorageAccessTokenProvider._
  private var keyfile: BlobId = _
  private var token: AccessTokenProvider.AccessToken = AccessTokenProviderUtil.Expired

  @transient
  private val encryptedStorage = EncryptedStorage()

  override def getAccessToken: AccessTokenProvider.AccessToken = {
    if (token.getExpirationTimeMilliSeconds < System.currentTimeMillis() + 300000L)
      token
    else {
      refresh()
      token
    }
  }

  override def refresh(): Unit = {
    val bytes = Util.readAllBytes(encryptedStorage.get(keyfile.getBucket, keyfile.getName))
    token = AccessTokenProviderUtil.getAccessTokenFromKeyFilePbBytes(bytes)
  }

  override def setConf(configuration: Configuration): Unit = {
    Option(configuration.get(GInitAccessTokenUri)) match {
      case Some(uri) =>
        Util.parseUri(uri) match {
          case Some(blobId) =>
            keyfile = blobId
          case _ =>
            throw new IllegalArgumentException(s"Invalid Access Token GCS URI '$uri'")
        }
      case _ =>
        throw new NoSuchElementException(s"$GInitAccessTokenUri not set in configuration")
    }
  }

  override def getConf: Configuration = {
    val conf = new Configuration()
    Option(keyfile).foreach{x =>
      conf.set(GInitAccessTokenUri, s"gs://${x.getBucket}/${x.getName}")
    }
    conf
  }
}
