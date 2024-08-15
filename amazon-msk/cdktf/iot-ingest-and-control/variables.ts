import * as dotenvx from "@dotenvx/dotenvx";
import { Construct } from "constructs";

export class UserVariables extends Construct {
  publicCertificateAuthority: boolean = false;
  createZillaPlusRole: boolean = false;
  createZillaPlusSecurityGroup: boolean = false;
  sshKeyEnabled: boolean = false;
  cloudwatchDisabled: boolean = false;
  mqttKafkaTopicCreationDisabled: boolean = false;

  constructor(scope: Construct, name: string) {
    super(scope, name);
    dotenvx.config({ quiet: true });

    this.createZillaPlusRole = process.env.CREATE_ZILLA_PLUS_ROLE !== "false";
    this.createZillaPlusSecurityGroup = process.env.CREATE_ZILLA_PLUS_SECURITY_GROUP !== "false";
    this.sshKeyEnabled = process.env.SSH_KEY_ENABLED === "true";
    this.cloudwatchDisabled = process.env.CLOUDWATCH_DISABLED === "true";
    this.mqttKafkaTopicCreationDisabled = process.env.MQTT_KAFKA_TOPIC_CREATION_DISABLED === "true";
  }
}
