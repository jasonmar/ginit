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

import com.google.crypto.tink.KeysetWriter
import com.google.crypto.tink.proto.{EncryptedKeyset, Keyset}
import org.apache.hadoop.conf.Configuration

/** Writes an EncryptedKeyset to Hadoop Configuration
  *
  * @param conf
  */
class KrbKeysetWriter(conf: Configuration) extends KeysetWriter {
  override def write(keyset: Keyset): Unit =
    throw new NotImplementedError()

  override def write(keyset: EncryptedKeyset): Unit =
    conf.set(KrbAccessTokenProvider.KrbKeyFileCipherText,
      Util.b64(keyset.getEncryptedKeyset))
}
