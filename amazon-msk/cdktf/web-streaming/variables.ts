import * as dotenvx from "@dotenvx/dotenvx";
import { Construct } from "constructs";

export class UserVariables extends Construct {
  customPath: boolean = false;
  publicCertificateAuthority: boolean = false;
  createZillaPlusRole: boolean = false;
  createZillaPlusSecurityGroup: boolean = false;
  sshKeyEnabled: boolean = false;
  cloudwatchDisabled: boolean = false;
  glueRegistryEnabled: boolean = false;
  kafkaTopicCreationDisabled: boolean = false;
  jwtEnabled: boolean = false;

  constructor(scope: Construct, name: string) {
    super(scope, name);
    dotenvx.config({ quiet: true });

    this.customPath = process.env.CUSTOM_PATH === "true";
    this.createZillaPlusRole = process.env.CREATE_ZILLA_PLUS_ROLE !== "false";
    this.createZillaPlusSecurityGroup = process.env.CREATE_ZILLA_PLUS_SECURITY_GROUP !== "false";
    this.sshKeyEnabled = process.env.SSH_KEY_ENABLED === "true";
    this.cloudwatchDisabled = process.env.CLOUDWATCH_DISABLED === "true";
    this.glueRegistryEnabled = process.env.GLUE_REGISTRY_ENABLED === "true";
    this.kafkaTopicCreationDisabled = process.env.KAFKA_TOPIC_CREATION_DISABLED === "true";
    this.jwtEnabled = process.env.JWT_ENABLED === "true";
  }
}
