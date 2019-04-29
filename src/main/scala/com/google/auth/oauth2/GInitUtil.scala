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

package com.google.auth.oauth2

import java.io.{ByteArrayInputStream, StringReader}
import java.net.URI
import java.nio.file.{Files, Paths}
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util
import java.util.Collections

import com.google.api.client.json.JsonObjectParser
import com.google.api.client.util.{PemReader, SecurityUtils}
import com.google.api.gax.core.{CredentialsProvider, FixedCredentialsProvider}
import com.google.cloud.proto.KeyFileProto.KeyFile
import com.google.common.collect.ImmutableList

object GInitUtil {
  private final val StorageReadWriteScope = "https://www.googleapis.com/auth/devstorage.read_write"
  private final val StorageReadOnlyScope = "https://www.googleapis.com/auth/devstorage.read_only"
  private final val CloudKMSScope = "https://www.googleapis.com/auth/cloudkms"

  private def privateKey(privateKeyPem: String): PrivateKey = {
    val keyReader = new StringReader(privateKeyPem)
    val keyEnc = PemReader.readFirstSectionAndClose(keyReader, "PRIVATE KEY")
      .getBase64DecodedBytes
    val keySpec = new PKCS8EncodedKeySpec(keyEnc)
    SecurityUtils.getRsaKeyFactory.generatePrivate(keySpec)
  }

  def getCredentialsProvider(path: Option[String] = None, readOnly: Boolean = true, readWrite: Boolean = false, kms: Boolean = false): CredentialsProvider = {
    val cp = getGoogleCredentials(path, scopes(readOnly, readWrite, kms))
    FixedCredentialsProvider.create(cp)
  }

  def scopes(readOnly: Boolean = false, readWrite: Boolean = false, kms: Boolean = false): util.Collection[String] = {
    require(readOnly || readWrite || kms, "must set one of readOnly|readWrite|kms")
    val buf = ImmutableList.builder[String]()
    if (readOnly) buf.add(StorageReadOnlyScope)
    if (readWrite) buf.add(StorageReadWriteScope)
    if (kms) buf.add(CloudKMSScope)
    buf.build
  }

  def getGoogleCredentials(path: Option[String] = None, scopes: util.Collection[String]): GoogleCredentials = {
    val creds = readJSONCredentials(path, scopes)
    createCredentialsFromPb(convertJson(creds), scopes)
  }

  def createCredentialsFromPb(keyFile: KeyFile, scopes: util.Collection[String] = Collections.emptyList()): GoogleCredentials = {
    if (keyFile.getType == "authorized_user") {
      val creds = UserCredentials.newBuilder()
        .setClientId(keyFile.getClientId)
        .setClientSecret(keyFile.getClientSecret)
        .setRefreshToken(keyFile.getRefreshToken)
        .setHttpTransportFactory(OAuth2Utils.HTTP_TRANSPORT_FACTORY)
        .build()
      if (scopes.isEmpty) creds
      else creds.createScoped(scopes)
    } else if (keyFile.getType == "service_account") {
      val creds = ServiceAccountCredentials.newBuilder()
        .setClientId(keyFile.getClientId)
        .setClientEmail(keyFile.getClientEmail)
        .setPrivateKey(privateKey(keyFile.getPrivateKey))
        .setPrivateKeyId(keyFile.getPrivateKeyId)
        .setScopes(scopes)
        .setHttpTransportFactory(OAuth2Utils.HTTP_TRANSPORT_FACTORY)
        .setTokenServerUri(URI.create(keyFile.getTokenUri))
        .setProjectId(keyFile.getProjectId)
        .build()
        .createScoped(scopes)
      if (scopes.isEmpty) creds
      else creds.createScoped(scopes)
    } else if (keyFile.getType == "access_token") {
      val accessToken = new AccessToken(keyFile.getAccessToken, new java.util.Date(keyFile.getExpirationTime))
      new GoogleCredentials(accessToken)
    } else {
      throw new IllegalArgumentException(s"unsupported credential type '${keyFile.getType}'")
    }
  }

  def readJSONCredentials(path: Option[String] = None, scopes: util.Collection[String]): CredentialsJson = {
    val credPath = path
      .orElse(sys.env.get("HOME").map(_ + "/.config/gcloud/application_default_credentials.json"))
      .getOrElse(sys.env("GOOGLE_APPLICATION_CREDENTIALS"))

    val adcPath = Paths.get(credPath)

    require(adcPath.toFile.exists(), "Application Default Credentials not found; please run `gcloud auth application-default login`")
    val is = new ByteArrayInputStream(Files.readAllBytes(adcPath))

    new JsonObjectParser(OAuth2Utils.JSON_FACTORY)
      .parseAndClose(is, OAuth2Utils.UTF_8, classOf[CredentialsJson])
  }

  def convertJson(creds: CredentialsJson): KeyFile = {
    val b = KeyFile.newBuilder()
    Option(creds.getType).foreach(b.setType)
    Option(creds.getClientSecret).foreach(b.setClientSecret)
    Option(creds.getRefreshToken).foreach(b.setRefreshToken)
    Option(creds.getProjectId).foreach(b.setProjectId)
    Option(creds.getPrivateKeyId).foreach(b.setPrivateKeyId)
    Option(creds.getPrivateKeyPem).foreach(b.setPrivateKey)
    Option(creds.getClientEmail).foreach(b.setClientEmail)
    Option(creds.getClientId).foreach(b.setClientId)
    Option(creds.getAuthUri).foreach(b.setAuthUri)
    Option(creds.getTokenUri).foreach(b.setTokenUri)
    Option(creds.getAuthProviderX509CertUrl).foreach(b.setAuthProviderX509CertUrl)
    Option(creds.getClientX509CertUrl).foreach(b.setClientX509CertUrl)
    b.build()
  }
}
