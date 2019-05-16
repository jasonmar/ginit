package com.google.cloud.ginit

import com.google.cloud.ginit.Util.Logging
import org.apache.hadoop.security.KrbTgt
import org.apache.spark.sql.SparkSession

object TestJob extends Logging {
  def main(args: Array[String]): Unit = {
    Util.configureLogging()
    val prin = args(0)
    val keyTabPath = args(1)
    val cache = args(2)

    val subject = KrbUtil.getSubject(prin, keyTabPath, Option(cache))
    KrbUtil.analyzeSubject(subject)

    val spark = SparkSession
      .builder()
      .getOrCreate()

    import spark.implicits._
    val ds = Seq(prin).toDS()
    val tickets = ds.map { principal =>
      val subject = KrbTgt.getSubjectFromCache(principal)
      KrbUtil.analyzeSubject(subject)
      val tickets = KrbTgt.getKerberosTicketsFromKRB5CC(principal)
      tickets.map(KrbUtil.printKerberosTicket).mkString("\n")
    }.collect()

    logger.info(s"KerberosTickets:\n$tickets")
  }

}
