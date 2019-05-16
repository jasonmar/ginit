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

import java.security.PublicKey
import java.util

import com.google.cloud.ginit.Util.Logging
import com.google.common.hash.Hashing
import com.google.crypto.tink.aead.AeadFactory
import com.google.crypto.tink.{Aead, CleartextKeysetHandle, KrbKeysetReader}
import javax.crypto.SecretKey
import javax.security.auth.Subject
import javax.security.auth.kerberos.{KerberosKey, KerberosPrincipal, KerberosTicket, KeyTab}
import javax.security.auth.login.{AppConfigurationEntry, Configuration, LoginContext}
import org.zeromq.codec.Z85

import scala.collection.JavaConverters.asScalaIteratorConverter
import scala.collection.mutable.ListBuffer

object KrbUtil extends Logging {
  /** Initializes a cryptographic primitive using Keyset
    * loaded from Kerberos KeyTab
    *
    * @param keyTabPath
    * @param principal
    * @return
    */
  def aeadFromKeyTab(keyTabPath: String, principal: String): Aead = {
    val reader = new KrbKeysetReader(principal, keyTabPath)
    AeadFactory.getPrimitive(CleartextKeysetHandle.read(reader))
  }

  def getSubject(principal: String, keyTabPath: String, cache: Option[String] = None): Subject = {
    val config = getConfiguration(principal, keyTabPath, cache)
    val loginContext = new LoginContext("", new Subject, null, config)
    loginContext.login()
    loginContext.getSubject
  }

  def getKerberosPrincipal(subject: Subject, principalName: String): Option[KerberosPrincipal] =
    getKerberosPrincipals(subject)
      .find(_.getName.equalsIgnoreCase(principalName))

  def getKerberosPrincipals(subject: Subject): Seq[KerberosPrincipal] =
    subject.getPrincipals(classOf[KerberosPrincipal])
      .iterator().asScala.toArray.toSeq

  case class PrivateCredentials(keyTabs: Seq[KeyTab], kerberosKeys: Seq[KerberosKey], kerberosTickets: Seq[KerberosTicket])

  def getPrivateCredentials(subject: Subject): PrivateCredentials = {
    val keyTabs = ListBuffer.empty[KeyTab]
    val kerberosKeys = ListBuffer.empty[KerberosKey]
    val kerberosTickets = ListBuffer.empty[KerberosTicket]

    subject.getPrivateCredentials()
      .iterator().asScala
      .foreach{
        case x: KeyTab =>
          keyTabs.append(x)
        case x: KerberosKey =>
          kerberosKeys.append(x)
        case x: KerberosTicket =>
          kerberosTickets.append(x)
        case x =>
          System.err.println(s"Unrecognized Private Credential type ${x.getClass.getCanonicalName.stripSuffix("$")}")
          Seq.empty
      }
    PrivateCredentials(keyTabs.result, kerberosKeys.result, kerberosTickets.result)
  }

  def getKerberosKeys(subject: Subject, principal: KerberosPrincipal, algorithm: String): Seq[KerberosKey] = {
    val creds = getPrivateCredentials(subject)
    (creds.keyTabs.flatMap(_.getKeys(principal)) ++
      creds.kerberosKeys)
      .filter{x =>
        x.getPrincipal == principal &&
          x.getAlgorithm == algorithm
      }
  }

  def findKerberosKey(subject: Subject, principalName: String, algorithm: String): Option[Array[Byte]] = {
    getKerberosPrincipal(subject, principalName) match {
      case Some(principal) =>
        getKerberosKeys(subject, principal, algorithm)
          .headOption.map(_.getEncoded)
      case _ =>
        System.out.println(s"KerberosPrincipal $principalName not found")
        None
    }
  }

  /** Prints the contents of a Kerberos Subject
    * which may contain multiple Principals,
    * each with multiple public and private credentials
    * @param subject
    */
  def analyzeSubject(subject: Subject): Unit = {
    getKerberosPrincipals(subject).foreach{p =>
      logger.info(printKerberosPrincipal(p))

      logger.info("Public Credentials:")
      subject.getPublicCredentials()
        .iterator().asScala.foreach{
        case x: KerberosKey =>
          logger.info(printKerberosKey(x))
        case x: PublicKey =>
          logger.info(printPublicKey(x))
        case x =>
          logger.info(s"""Unrecognized Public Credential type: ${x.getClass.getCanonicalName.stripSuffix("$")}""")
      }

      logger.info("Private Credentials:")
      val priv = getPrivateCredentials(subject)

      // KeyTab
      priv.keyTabs.foreach { x =>
        logger.info("KeyTab:")
        x.getKeys(p).foreach { k =>
          logger.info(printKerberosKey(k))
        }
      }

      // KerberoKey
      priv.kerberosKeys.foreach { x =>
        logger.info(printKerberosKey(x))
      }

      // KerberosTicket
      priv.kerberosTickets.foreach { x =>
        logger.info(printKerberosTicket(x))
      }
    }
  }

  def printKerberosPrincipal(principal: KerberosPrincipal): String =
    s"""KerberosPrincipal
       |  name: ${principal.getName}
       |  type: ${principal.getNameType}
       |  realm: ${principal.getRealm}""".stripMargin

  def printPublicKey(key: PublicKey): String =
    s"""PublicKey(algorithm = "${key.getAlgorithm}", format = "${key.getFormat}", length = ${key.getEncoded.length}, z85 = ${z85sha256(key.getEncoded)})""".stripMargin

  def printKerberosKey(k: KerberosKey): String =
    s"""KerberosKey:
       |  principal: ${k.getPrincipal.getName}
       |  keyType:   ${k.getKeyType}
       |  version:   ${k.getVersionNumber}
       |  algorithm: ${k.getAlgorithm}
       |  format:    ${k.getFormat}
       |  length:    ${k.getEncoded.length}
       |  z85sha256: ${z85sha256(k.getEncoded)}""".stripMargin

  def z85(a: Array[Byte], n: Int = 6): String =
    Z85.Z85Encoder(a).take(n) + "..."

  def z85sha256(a: Array[Byte]): String = {
    val hash = Hashing.sha256().hashBytes(a).asBytes()
    Z85.Z85Encoder(hash)
  }

  def printKerberosTicket(x: KerberosTicket): String =
    s"""KerberosTicket:
       |  principal:      ${x.getClient.getName}
       |  authTime:       ${x.getAuthTime}
       |  startTime:      ${x.getStartTime}
       |  endTime:        ${x.getEndTime}
       |  renewTill:      ${x.getRenewTill}
       |  bytes:          ${x.getEncoded.length}
       |  sessionKeyType: ${x.getSessionKeyType}
       |  sessionKey:     ${printSecretKey(x.getSessionKey)}""".stripMargin

  def printSecretKey(k: SecretKey): String =
    s"""SecretKey(algorithm = ${k.getAlgorithm}, format = ${k.getFormat}, length = ${k.getEncoded.length}, z85 = ${z85sha256(k.getEncoded)})""".stripMargin

  def getConfiguration(principal: String, keyTabPath: String, cache: Option[String]): Configuration = {
    new Configuration() {
      override def getAppConfigurationEntry(name: String): Array[AppConfigurationEntry] = {
        val options: util.Map[String, String] = new util.HashMap[String, String]
        options.put("principal", principal)
        options.put("keyTab", keyTabPath)
        options.put("doNotPrompt", "true")
        options.put("useKeyTab", "true")
        options.put("storeKey", "true")
        options.put("isInitiator", "true")
        cache.foreach{ticketCache =>
          options.put("useTicketCache", "true")
          options.put("ticketCache", ticketCache)
        }
        Array[AppConfigurationEntry](new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule", AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options))
      }
    }
  }
}
