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

import com.google.auth.oauth2.GInitUtil
import com.google.cloud.hadoop.util.AccessTokenProvider
import com.google.cloud.proto.KeyFileProto.KeyFile

object AccessTokenProviderUtil {
  val AccessTokenProviderImpl = "fs.gs.auth.access.token.provider.impl"
  val Expired = new AccessTokenProvider.AccessToken("", -1L)

  def getAccessTokenFromKeyFilePbBytes(bytes: Array[Byte]): AccessTokenProvider.AccessToken = {
    val keyFile = KeyFile.parseFrom(bytes)
    if (keyFile.getType == "access_token") {
      new AccessTokenProvider.AccessToken(keyFile.getAccessToken, keyFile.getExpirationTime)
    } else {
      val token = GInitUtil.createCredentialsFromPb(keyFile)
        .refreshAccessToken()
      new AccessTokenProvider.AccessToken(token.getTokenValue, token.getExpirationTime.getTime)
    }
  }
}
