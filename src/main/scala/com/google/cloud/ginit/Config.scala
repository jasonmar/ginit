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


case class Config(tokenBucket: String = "",
                  kmsKeyId: String = "",
                  project: String = "",
                  principal: String = "",
                  keyTabPath: String = "",
                  remoteKeyTabPath: String = "",
                  confFile: String = "ginit.xml",
                  mode: Config.Mode = Config.Kms,
                  refreshToken: Boolean = false,
                  readOnly: Boolean = false)

object Config {
  sealed trait Mode
  case object Kms extends Mode
  case object Krb extends Mode

  def parse(args: Array[String]): Option[Config] = Parser.parse(args, Config())

  final val Parser = new scopt.OptionParser[Config]("GInit") {
    head("GInit", "0.1.0")

    arg[String]("confFile")
      .action{(x, c) => c.copy(confFile = x)}
      .text("Hadoop Configuration XML file (default: ginit.xml)")

    arg[Boolean]("readOnly")
      .action{(x, c) => c.copy(readOnly = x)}
      .text("Create access token with 'devstorage.read_only' storage scope (default: false)")

    arg[Boolean]("refreshToken")
      .action{(x, c) => c.copy(refreshToken = x)}
      .text("Store refresh token (default: false)")

    cmd("krb")
      .action{(_,c)  => c.copy(mode = Krb)}
      .children(
        arg[String]("principal")
          .required()
          .action{(x, c) => c.copy(principal = x)}
          .text("Kerberos Principal 'user@EXAMPLE.COM' or 'service/HOSTNAME.EXAMPLE.COM'"),

        arg[String]("keyTabPath")
          .required()
          .action{(x, c) => c.copy(keyTabPath = x)}
          .text("Kerberos KeyTab path"),

        arg[String]("remoteKeyTabPath")
          .required()
          .action{(x, c) => c.copy(remoteKeyTabPath = x)}
          .text("Kerberos KeyTab path on Hadoop node"),

        checkConfig{c =>
          if (c.principal.isEmpty)
            failure("must provide --principal")
          else if (c.keyTabPath.isEmpty)
            failure("must provide --keyTabPath")
          else success
        }
      )

    cmd("kms")
      .action{(_,c)  => c.copy(mode = Kms)}
      .children(
        arg[String]("tokenBucket")
          .required()
          .action{(x, c) => c.copy(tokenBucket = x)}
          .text("GCS Bucket used for token storage"),

        arg[String]("kmsKeyId")
          .action{(x, c) => c.copy(kmsKeyId = x)}
          .text("KMS key id 'projects/*/locations/*/keyRings/*/cryptoKeys/*'"),

        arg[String]("project")
          .required()
          .action{(x, c) => c.copy(project = x)}
          .text("Project ID"),

        checkConfig{c =>
          if (c.kmsKeyId.isEmpty)
            failure("invalid KMS CryptoKey ID")
          else success
        }
      )

    help("help").text("prints this usage text")

    note("GInit stores a Google IAM Access Token in Hadoop Configuration or GCS with KMS envelope encryption and writes a Hadoop Configuration XML to configure the GCS connector to use the stored access token for user credentials")
  }
}
