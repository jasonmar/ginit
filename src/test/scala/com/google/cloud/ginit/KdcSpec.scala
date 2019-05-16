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

import java.io.File
import java.nio.file.{Files, Paths}

import org.apache.kerby.kerberos.kerb.`type`.ticket.TgtTicket
import org.apache.kerby.kerberos.kerb.server.{KdcConfig, KdcConfigKey, SimpleKdcServer}
import org.scalatest.FlatSpec

object KdcSpec {
  def startKdc(realm: String, principal: String, keyTabPath: String): Unit = {
    val kdc = new SimpleKdcServer()
    kdc.setAllowTcp(false)
    kdc.setAllowUdp(true)
    kdc.setKdcHost("127.0.0.1")
    kdc.setKdcRealm(realm)
    kdc.setKdcUdpPort(8089)
    kdc.init()
    kdc.start()
    val cfg = kdc.getKdcConfig
    cfg.setString(KdcConfigKey.KRB_DEBUG, "true")
    cfg.setString(KdcConfigKey.ENCRYPTION_TYPES, "aes256-cts-hmac-sha1-96")

    kdc.createPrincipal(principal)
    kdc.createPrincipal(s"HTTP/localhost@$realm")
    kdc.exportPrincipals(new File(keyTabPath))
  }
}

class KdcSpec extends FlatSpec {
  val TempDir = Files.createTempDirectory("kdcspec").toFile
  val TestRealm = "EXAMPLE.COM"
  val TestPrincipal = s"user@$TestRealm"

  "KrbUtil" should "extract private key" in {
    val keyTabFile = Paths.get(TempDir.toURI).resolve("user.keytab").toFile
    val keyTabPath = keyTabFile.getAbsolutePath

    KdcSpec.startKdc(TestRealm, TestPrincipal, keyTabPath)


    val subject = KrbUtil.getSubject(TestPrincipal, keyTabPath)
    val serverSubject = KrbUtil.getSubject("HTTP/localhost@EXAMPLE.COM", keyTabPath)
    KrbUtil.analyzeSubject(subject)
    KrbUtil.analyzeSubject(serverSubject)

    val key = KrbUtil.findKerberosKey(subject, TestPrincipal, "AES128")
    key.foreach{x =>
      System.out.println(s"Found AES128 key with length ${x.length}")
    }
  }

}
