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
import com.google.common.base.Charsets
import com.google.common.io.BaseEncoding
import com.google.crypto.tink.Aead
import org.apache.hadoop.conf.Configuration

object KrbAccessTokenProvider {
  val ClassName: String = "com.google.cloud.ginit.KrbAccessTokenProvider"
  val KrbKeyFileCipherText = "fs.gs.auth.krb.keyfile.ciphertext"
  val KrbPrincipal = "fs.gs.auth.krb.principal"
  val KrbKeyTabPath = "fs.gs.auth.krb.keytab"

  def buildConf(keyFileCipherText: Array[Byte], principal: String, keyTabPath: String): Configuration = {
    val conf = new Configuration(false)
    conf.set(KrbKeyFileCipherText, BaseEncoding.base64.encode(keyFileCipherText))
    conf.set(KrbPrincipal, principal)
    conf.set(KrbKeyTabPath, keyTabPath)
    conf.set(AccessTokenProviderUtil.AccessTokenProviderImpl, ClassName)
    conf
  }
}

class KrbAccessTokenProvider extends AccessTokenProvider {
  import KrbAccessTokenProvider._
  private var encryptedKeyFileBytes: Array[Byte] = _
  private var principal: String = _
  private var keyTabPath: String = _
  private var token: AccessTokenProvider.AccessToken = AccessTokenProviderUtil.Expired
  private var aead: Option[Aead] = None

  override def getAccessToken: AccessTokenProvider.AccessToken = {
    val valid = token.getToken.nonEmpty &&
      (System.currentTimeMillis() + 300000L) < token.getExpirationTimeMilliSeconds
    if (valid) {
      token
    } else {
      refresh()
      token
    }
  }

  def getAead: Aead = {
    if (aead.isEmpty)
      aead = Option(KrbUtil.aeadFromKeyTab(keyTabPath, principal))
    aead.get
  }

  override def refresh(): Unit = {
    val bytes = getAead.decrypt(encryptedKeyFileBytes, principal.getBytes(Charsets.UTF_8))
    token = AccessTokenProviderUtil.getAccessTokenFromKeyFilePbBytes(bytes)
  }

  override def setConf(configuration: Configuration): Unit = {
    Option(configuration.get(KrbKeyFileCipherText)) match {
      case Some(s) =>
        encryptedKeyFileBytes = BaseEncoding.base64.decode(s)
      case _ =>
        throw new NoSuchElementException(s"$KrbKeyFileCipherText not set in configuration")
    }
    Option(configuration.get(KrbPrincipal)) match {
      case Some(s) =>
        principal = s
      case _ =>
        throw new NoSuchElementException(s"$KrbPrincipal not set in configuration")
    }
    Option(configuration.get(KrbKeyTabPath)) match {
      case Some(s) =>
        keyTabPath = s
      case _ =>
        throw new NoSuchElementException(s"$KrbKeyTabPath not set in configuration")
    }
    getAead
  }

  override def getConf: Configuration =
    buildConf(encryptedKeyFileBytes, principal, keyTabPath)
}
