name := "ginit"

scalaVersion := "2.11.8"

organization := "com.google.cloud"

version := "0.1.0-SNAPSHOT"

val exGuava = ExclusionRule(organization = "com.google.guava")
val exlog4j = ExclusionRule(organization = "log4j")

libraryDependencies ++= Seq(
  "com.google.crypto.tink" % "tink" % "1.2.2" ,
  "com.google.protobuf" % "protobuf-java" % "3.7.1",
  "com.google.protobuf" % "protobuf-java-util" % "3.7.1",
  "com.fasterxml.jackson.dataformat" % "jackson-dataformat-xml" % "2.9.8",
  "com.google.api-client" % "google-api-client" % "1.28.0",
  "com.google.cloud" % "google-cloud-bigquery" % "1.71.0",
  "com.google.cloud" % "google-cloud-storage" % "1.71.0",
  "com.google.cloud" % "google-cloud-kms" % "0.81.0-beta",
  "com.google.cloud.bigdataoss" % "gcs-connector" % "hadoop2-1.9.16" % Provided excludeAll exlog4j,
  "org.apache.spark" %% "spark-core" % "2.4.3" % Provided,
  "org.apache.spark" %% "spark-sql" % "2.4.3" % Provided,
  "org.apache.hadoop" % "hadoop-common" % "2.9.2" % Provided,
  "org.apache.commons" % "commons-configuration2" % "2.4",
  "org.slf4j" % "slf4j-api" % "1.7.26",
  "commons-collections" % "commons-collections" % "3.2.2",
  "com.github.scopt" %% "scopt" % "3.7.1",
  "org.scalatest" %% "scalatest" % "3.0.5" % Test,
  "org.apache.kerby" % "kerb-simplekdc" % "2.0.0" % Test
).map(_ excludeAll exGuava)

libraryDependencies ++= Seq(
  "com.google.guava" % "guava" % "27.0.1-jre"
)

mainClass in assembly := Some("com.google.cloud.ginit.GInit")

assemblyJarName in assembly := "ginit.jar"
assemblyJarName in assemblyPackageDependency := "ginit.dep.jar"

// Don't run tests during assembly
test in assembly := Seq()

assemblyMergeStrategy in assembly := {
  case PathList("META-INF", _) => MergeStrategy.discard
  case _ => MergeStrategy.first
}