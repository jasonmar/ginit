package org.apache.hadoop.security

import javax.security.auth.Subject
import javax.security.auth.kerberos.KerberosTicket

import scala.collection.JavaConverters._

object KrbTgt {
  private val KRB5CC = sys.env.get("KRB5CC")
    .orElse(sys.env.get("LOGNAME").map(uid => s"/tmp/krb5cc_$uid"))

  def getSubjectFromCache(principalName: String, krb5cc: Option[String] = None): Subject = {
    UserGroupInformation
      .getUGIFromTicketCache(krb5cc.orElse(KRB5CC).orNull, principalName)
      .getSubject
  }

  def getKerberosTicketsFromKRB5CC(principalName: String, krb5cc: Option[String] = None): Seq[KerberosTicket] ={
    getSubjectFromCache(principalName, krb5cc.orElse(KRB5CC))
      .getPrivateCredentials(classOf[KerberosTicket])
      .asScala
      .toArray
      .toSeq
  }

  def filterKerberosTickets(krbTickets: Seq[KerberosTicket], isOriginalTGT: Boolean = true): Seq[KerberosTicket] = {
    krbTickets.filter{x =>
      val principal = x.getServer
      val realm = principal.getRealm
      val tgtPrincipal = s"krbtgt/$realm@$realm"
      if (isOriginalTGT)
        principal.getName == tgtPrincipal
      else
        principal.getName != tgtPrincipal
    }
  }
}
