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
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer
import org.scalatest.FlatSpec

object KdcSpec {
  def startKdc(realm: String, principal: String, keyTabPath: String): Unit = {
    val kdc = new SimpleKdcServer()
    kdc.setAllowTcp(true)
    kdc.setKdcHost("localhost")
    kdc.setKdcRealm(realm)
    kdc.setKdcTcpPort(8088)
    kdc.init()
    kdc.start()
    kdc.createPrincipal(principal)
    kdc.exportPrincipals(new File(keyTabPath))
  }
}

class KdcSpec extends FlatSpec {
  val TempDir = Files.createTempDirectory("kdcspec").toFile
  val TestRealm = "EXAMPLE.com"
  val TestPrincipal = s"user@$TestRealm"

  "KrbUtil" should "extract private key" in {
    val keyTabFile = Paths.get(TempDir.toURI).resolve("user.keytab").toFile
    val keyTabPath = keyTabFile.getAbsolutePath

    KdcSpec.startKdc(TestRealm, TestPrincipal, keyTabPath)


    val subject = KrbUtil.getSubject(TestPrincipal, keyTabPath)
    KrbUtil.analyzeSubject(subject)

    val key = KrbUtil.findKerberosKey(subject, TestPrincipal, "AES128")
    key.foreach{x =>
      System.out.println(s"Found AES128 key with length ${x.length}")
    }
  }

  def printTgt(tgt: TgtTicket): String = {
    val ticket = tgt.getTicket
    s"""TgtTicket:
       |  sname:       ${ticket.getSname.getName}
       |  snameType:   ${ticket.getSname.getNameType.getName}
       |  tktvno:      ${ticket.getTktvno}
       |  realm:       ${ticket.getRealm}
       |  EncPart
       |    authTime:  ${ticket.getEncPart.getAuthTime.getTimeInSeconds}
       |    startTime: ${ticket.getEncPart.getStartTime.getTimeInSeconds}
       |    endTime:   ${ticket.getEncPart.getEndTime.getTimeInSeconds}
       |    cname:     ${ticket.getEncPart.getCname.getName}
       |    crealm:    ${ticket.getEncPart.getCrealm}
       |  Key
       |    bytes:     ${ticket.getEncPart.getKey.getKeyData.length}
       |    type:      ${ticket.getEncPart.getKey.getKeyType.getName}
       |    kvno:      ${ticket.getEncPart.getKey.getKvno}
       |  etype:       ${ticket.getEncryptedEncPart.getEType.getName}
       |  kvno:        ${ticket.getEncryptedEncPart.getKvno}""".stripMargin
  }

}
