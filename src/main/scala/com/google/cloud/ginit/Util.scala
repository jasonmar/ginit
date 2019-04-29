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

import java.io.{ByteArrayInputStream, ByteArrayOutputStream}
import java.nio.ByteBuffer
import java.nio.channels.{Channels, FileChannel, ReadableByteChannel, WritableByteChannel}
import java.nio.file.{Path, StandardOpenOption}

import com.google.auth.oauth2.AccessToken
import com.google.cloud.proto.KeyFileProto.KeyFile
import com.google.cloud.storage.BlobId
import com.google.common.base.Charsets
import com.google.common.hash.Hashing
import com.google.common.io.BaseEncoding
import com.google.protobuf.ByteString

object Util {
  def parseUri(gsUri: String): Option[BlobId] = {
    if (gsUri.length < 6 || gsUri.substring(0, 5) != "gs://") {
      None
    } else {
      val dest = gsUri.substring(5, gsUri.length)
      val bucket = dest.substring(0, dest.indexOf('/'))
      val name = dest.substring(dest.indexOf('/')+1, dest.length)
      Option(BlobId.of(bucket, name))
    }
  }

  def transfer(rc: ReadableByteChannel, wc: WritableByteChannel, chunkSize: Int = 4096): Unit = {
    val buf = ByteBuffer.allocate(chunkSize)
    while (rc.read(buf) > -1) {
      buf.flip()
      wc.write(buf)
      buf.clear()
    }
    rc.close()
    wc.close()
  }

  def pathChannel(path: Path): ReadableByteChannel =
    FileChannel.open(path, StandardOpenOption.READ)

  def byteChannel(bytes: Array[Byte]): ReadableByteChannel =
    Channels.newChannel(new ByteArrayInputStream(bytes))

  def stringChannel(s: String): ReadableByteChannel =
    byteChannel(utf8(s))

  def utf8(s: String): Array[Byte] =
    s.getBytes(Charsets.UTF_8)

  def utf8(rc: ReadableByteChannel): String =
    utf8(readAllBytes(rc))

  def utf8(bytes: Array[Byte]): String =
    new String(bytes, Charsets.UTF_8)

  def readAllBytes(rc: ReadableByteChannel, chunkSize: Int = 4096): Array[Byte] = {
    val os = new ByteArrayOutputStream()
    val wc = Channels.newChannel(os)
    Util.transfer(rc, wc, chunkSize)
    os.toByteArray
  }

  def createKeyFile(token: AccessToken): KeyFile = {
    KeyFile.newBuilder()
      .setType("access_token")
      .setExpirationTime(token.getExpirationTime.getTime)
      .setAccessToken(token.getTokenValue)
      .build()
  }

  def hashKeyFile(keyFile: KeyFile): String =
    hash(keyFile.toByteArray)

  def hash(bytes: Array[Byte]): String =
    Hashing.sha256().hashBytes(bytes).toString

  def hash(byteString: ByteString): String =
    Hashing.sha256().hashBytes(byteString.toByteArray).toString

  def b64(bytes: Array[Byte]): String =
    BaseEncoding.base64.encode(bytes)

  def b64(byteString: ByteString): String =
    b64(byteString.toByteArray)
}
