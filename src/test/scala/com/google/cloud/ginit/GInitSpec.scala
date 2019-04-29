package com.google.cloud.ginit

import java.io.ByteArrayOutputStream
import java.nio.channels.Channels
import java.nio.file.{Files, Paths}
import java.util.Collections

import com.google.auth.oauth2.GInitUtil
import com.google.cloud.ginit.Config.Krb
import com.google.cloud.hadoop.gcsio.{GoogleCloudStorageImpl, GoogleCloudStorageOptions, StorageResourceId}
import com.google.cloud.hadoop.util.{AccessTokenProviderClassFromConfigFactory, CredentialFromAccessTokenProviderClassFactory}
import com.google.cloud.storage.StorageOptions
import com.google.common.base.Charsets
import com.google.common.hash.Hashing
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.streamingaead.{StreamingAeadConfig, StreamingAeadFactory}
import org.apache.hadoop.conf.Configuration
import org.scalatest.{BeforeAndAfterAll, FlatSpec}

import scala.util.Random

class GInitSpec extends FlatSpec with BeforeAndAfterAll {
  val TestProject = sys.env("PROJECT")
  val TestTokenBucket = sys.env("TOKEN_BUCKET")
  val TestKeyId = sys.env("KMS_KEYID")
  val TestDataBucket = sys.env("DATA_BUCKET")

  override def beforeAll(): Unit = {
    AeadConfig.register()
    StreamingAeadConfig.register()
  }

  def fixture = new {
    val testString: String = Random.nextString(3 * 4096)
  }

  "GInit" should "get AccessToken" in {
    val json = GInitUtil.readJSONCredentials(scopes = GInitUtil.scopes(readWrite = true))
    val keyFile = GInitUtil.convertJson(json)
    val creds = GInitUtil.createCredentialsFromPb(keyFile)
    val token = creds.refreshAccessToken()
    assert(token.getExpirationTime.getTime > System.currentTimeMillis)
    System.out.println(s"token: ${token.getTokenValue.substring(0,20)}\nexpiration: ${token.getExpirationTime}")
  }


  it should "transfer bytes" in {
    val f = fixture
    import f._

    val readBytes = Util.readAllBytes(Util.stringChannel(testString))
    compare(readBytes, testString)
  }

  it should "encrypt and decrypt" in {
    val f = fixture
    import f._

    val os = new ByteArrayOutputStream()
    val iv = EncryptedStorage.genIv
    val streamingAead = StreamingAeadFactory.getPrimitive(KeysetHandle.generateNew(EncryptedStorage.KeyTemplate))
    val wc = streamingAead.newEncryptingChannel(Channels.newChannel(os), iv.getIV)

    Util.transfer(Util.stringChannel(testString), wc)

    val cipherText = os.toByteArray

    val readBytes = Util.readAllBytes(streamingAead.newDecryptingChannel(Util.byteChannel(cipherText), iv.getIV))

    compare(readBytes, testString)
  }

  it should "read encrypted files" in {
    val f = fixture
    import f._
    val testName = "enc_test_1"

    val encryptedStorage = {
      val storage = StorageOptions.newBuilder()
        .setCredentials(GInitUtil.getCredentialsProvider(readWrite = true).getCredentials)
        .build().getService
      new EncryptedStorage(GcpKms(), storage)
    }

    encryptedStorage.put(TestTokenBucket, testName, Util.stringChannel(testString), TestKeyId.stripPrefix("gcp-kms://"))
    val readBytes = Util.readAllBytes(encryptedStorage.get(TestTokenBucket, testName))

    compare(readBytes, testString)
  }

  it should "write then read with refresh token" in {
    val f = fixture
    import f._

    val config1 = Config(TestTokenBucket, TestKeyId, TestProject, confFile = "ginit-kms.xml",refreshToken = true)

    runWithConfig(config1, testString, TestDataBucket, "testfile_gcs_connector_plaintext_refreshtoken.txt", EncryptedStorageAccessTokenProvider.ClassName)
  }

  it should "write then read with access token" in {
    val f = fixture
    import f._

    val config = Config(TestTokenBucket, TestKeyId, TestProject, confFile = "ginit-kms2.xml", refreshToken = false)

    runWithConfig(config, testString, TestDataBucket,"testfile_gcs_connector_plaintext_accesstoken.txt", EncryptedStorageAccessTokenProvider.ClassName)
  }

  it should "use kerberos" in {
    val f = fixture
    import f._

    val tempDir = Files.createTempDirectory("kdcspec").toFile
    val testRealm = "EXAMPLE.com"
    val testPrincipal = s"user@$testRealm"
    val keyTabFile = Paths.get(tempDir.toURI).resolve("user.keytab").toFile
    val keyTabPath = keyTabFile.getAbsolutePath

    KdcSpec.startKdc(testRealm, testPrincipal, keyTabPath)

    val config = Config(TestTokenBucket, TestKeyId, TestProject, principal = testPrincipal, keyTabPath = keyTabPath, remoteKeyTabPath = keyTabPath, mode = Krb, refreshToken = true)

    runWithConfig(config, testString, TestDataBucket, "testfile_gcs_connector_plaintext_accesstoken.txt", KrbAccessTokenProvider.ClassName)
  }


  def compare(readBytes: Array[Byte], testString: String): Unit = {
    val readHash = Hashing.sha256().hashBytes(readBytes).toString
    val testHash = Hashing.sha256().hashString(testString, Charsets.UTF_8).toString
    assert(readHash == testHash)
  }

  def runWithConfig(config: Config, testString: String, testBucket: String, testObjectName: String, accessTokenProviderImpl: String): Unit = {
    val json = GInitUtil.readJSONCredentials(scopes = GInitUtil.scopes(readWrite = true))
    val keyFile = GInitUtil.convertJson(json)
    val uri = s"gs://${config.tokenBucket}/${Util.hashKeyFile(keyFile)}"
    assert(keyFile.getType == "authorized_user")

    GInit.run(config)

    val conf: Configuration =
      if (accessTokenProviderImpl == KrbAccessTokenProvider.ClassName) {
        val conf1 = new Configuration(false)
        conf1.addResource(Paths.get(config.confFile).toUri.toURL)
        conf1
      } else {
        EncryptedStorageAccessTokenProvider.buildConf(uri)
      }
    assert(Option(conf.get(AccessTokenProviderUtil.AccessTokenProviderImpl)).isDefined)

    val atp = if (accessTokenProviderImpl == EncryptedStorageAccessTokenProvider.ClassName) {
      new EncryptedStorageAccessTokenProvider
    } else {
      new KrbAccessTokenProvider
    }
    atp.setConf(conf)

    // Do the things GCS connector does to get a credential
    val atpcfcf = new AccessTokenProviderClassFromConfigFactory()
      .withOverridePrefix("fs.gs")

    val credential = Option(CredentialFromAccessTokenProviderClassFactory.credential(atpcfcf, conf, Collections.emptyList()))
    assert(credential.isDefined)

    val gcsOptions = GoogleCloudStorageOptions.newBuilder()
      .setAppName("GInitSpec")
      .setProjectId(config.project)
      .build()

    val gcsConnector = new GoogleCloudStorageImpl(gcsOptions, credential.get)

    val testObject = StorageResourceId.fromObjectName(s"gs://$testBucket/$testObjectName")

    // Write the object
    val wc = gcsConnector.create(testObject)
    val rc = Util.stringChannel(testString)
    Util.transfer(rc, wc)

    val readBytes = Util.readAllBytes(gcsConnector.open(testObject))

    compare(readBytes, testString)
  }
}
