import { Construct } from "constructs";
import { App, TerraformStack, TerraformOutput, TerraformVariable, Fn, Op } from "cdktf";
import { AwsProvider } from "@cdktf/provider-aws/lib/provider";
import { Lb } from "@cdktf/provider-aws/lib/lb";
import { LbListener } from "@cdktf/provider-aws/lib/lb-listener";
import { dataAwsAmi, launchTemplate } from "@cdktf/provider-aws";
import { autoscalingGroup } from "@cdktf/provider-aws";
import { LbTargetGroup } from "@cdktf/provider-aws/lib/lb-target-group";
import { DataAwsSecretsmanagerSecretVersion } from "@cdktf/provider-aws/lib/data-aws-secretsmanager-secret-version";
import { CloudwatchLogGroup } from "@cdktf/provider-aws/lib/cloudwatch-log-group";
import { DataAwsMskCluster } from "@cdktf/provider-aws/lib/data-aws-msk-cluster";
import instanceTypes from "./instance-types";
import { DataAwsRegion } from "@cdktf/provider-aws/lib/data-aws-region";
import { DataAwsAvailabilityZones } from "@cdktf/provider-aws/lib/data-aws-availability-zones";
import { DataAwsMskBrokerNodes } from "@cdktf/provider-aws/lib/data-aws-msk-broker-nodes";
import { DataAwsSubnet } from "@cdktf/provider-aws/lib/data-aws-subnet";
import { DataAwsSubnets } from "@cdktf/provider-aws/lib/data-aws-subnets";
import { DataAwsVpc } from "@cdktf/provider-aws/lib/data-aws-vpc";
import { InternetGateway } from "@cdktf/provider-aws/lib/internet-gateway";
import { Route } from "@cdktf/provider-aws/lib/route";
import { RouteTable } from "@cdktf/provider-aws/lib/route-table";
import { RouteTableAssociation } from "@cdktf/provider-aws/lib/route-table-association";
import { Subnet } from "@cdktf/provider-aws/lib/subnet";
import { IamInstanceProfile } from "@cdktf/provider-aws/lib/iam-instance-profile";
import { IamRole } from "@cdktf/provider-aws/lib/iam-role";
import { IamRolePolicy } from "@cdktf/provider-aws/lib/iam-role-policy";
import { SecurityGroup } from "@cdktf/provider-aws/lib/security-group";

import { UserVariables } from "./variables";

export class ZillaPlusIotAndControlStack extends TerraformStack {
  constructor(scope: Construct, id: string) {
    super(scope, id);
    const userVariables = new UserVariables(this, "main");

    const awsProvider = new AwsProvider(this, "AWS", {});

    const region = new DataAwsRegion(this, "CurrentRegion", {
      provider: awsProvider,
    });

    const mskClusterName = new TerraformVariable(this, "msk_cluster_name", {
      type: "string",
      description: "The name of the MSK cluster",
    });

    const mskCluster = new DataAwsMskCluster(this, "MSKCluster", {
      clusterName: mskClusterName.stringValue,
    });

    const mskAccessCredentialsName = new TerraformVariable(this, "msk_access_credentials_name", {
      type: "string",
      description: "The MSK Access Credentials Secret Name with JSON properties; username, password",
    });
    // Validate that the Credentials exists
    const secret = new DataAwsSecretsmanagerSecretVersion(this, "mskAccessCredentials", {
      secretId: mskAccessCredentialsName.stringValue,
    });

    const mskClusterBrokerNodes = new DataAwsMskBrokerNodes(this, "MSKClusterBrokerNodes", {
      clusterArn: mskCluster.arn,
    });

    const subnetId = mskClusterBrokerNodes.nodeInfoList.get(0).clientSubnet;

    const subnet = new DataAwsSubnet(this, "Subnet", {
      id: subnetId,
    });

    const vpc = new DataAwsVpc(this, "Vpc", {
      id: subnet.vpcId,
    });

    const subnets = new DataAwsSubnets(this, "PublicSubnets", {
      filter: [
        {
          name: "vpc-id",
          values: [vpc.id],
        },
      ],
    });

    const igw = new InternetGateway(this, "InternetGateway", {
      vpcId: vpc.id,
      tags: {
        Name: "my-igw",
      },
    });

    const publicRouteTable = new RouteTable(this, "PublicRouteTable", {
      vpcId: vpc.id,
      tags: {
        Name: "public-route-table",
      },
    });

    new Route(this, "PublicRoute", {
      routeTableId: publicRouteTable.id,
      destinationCidrBlock: "0.0.0.0/0",
      gatewayId: igw.id,
    });

    const availabilityZones = new DataAwsAvailabilityZones(this, "AZs", {});
    const subnetOffset = subnets.ids.length;
    const subnetMask = Fn.parseint(Fn.element(Fn.split("/", vpc.cidrBlock), 1), 10);
    const availableIpv4 = subnet.availableIpAddressCount;
    // Math magic to find next power of 2 and based on that the subnetAddressPower
    const subnetAddressPower = Fn.log(Fn.pow(2, Fn.ceil(Fn.log(availableIpv4, 2))), 2);
    const subnetsMax = Op.sub(32, Op.add(subnetAddressPower, subnetMask));

    const subnetIds = [];
    for (let i = 1; i < 3; i++) {
      const az = Fn.element(availabilityZones.names, i);
      const subnetIndex = subnetOffset + i;
      const cidrBlock = Fn.cidrsubnet(vpc.cidrBlock, subnetsMax, subnetIndex + i);

      const subnet = new Subnet(this, `PublicSubnet${i}`, {
        vpcId: vpc.id,
        cidrBlock: cidrBlock,
        availabilityZone: az,
        mapPublicIpOnLaunch: true,
        tags: {
          Name: `public-subnet--${subnetIndex + 1}`,
        },
      });

      subnetIds.push(subnet.id);

      new RouteTableAssociation(this, `PublicSubnet${i}RouteTableAssociation`, {
        subnetId: subnet.id,
        routeTableId: publicRouteTable.id,
      });
    }

    const kafkaTopicMqttSessions = new TerraformVariable(this, "kafka_topic_mqtt_sessions", {
      type: "string",
      description: 'The Kafka topic storing MQTT sessions, cleanup policy "compact"',
      default: "mqtt-sessions",
    });

    const kafkaTopicMqttMessages = new TerraformVariable(this, "kafka_topic_mqtt_messages", {
      type: "string",
      description: 'The Kafka topic storing MQTT messages, cleanup policy "delete"',
      default: "mqtt-messages",
    });

    const kafkaTopicMqttRetained = new TerraformVariable(this, "kafka_topic_mqtt_retained", {
      type: "string",
      description: 'The Kafka topic storing MQTT retained, cleanup policy "compact"',
      default: "mqtt-retained",
    });

    const secretValue = Fn.jsondecode(secret.secretString);
    const username = Fn.lookup(secretValue, "username");
    const password = Fn.lookup(secretValue, "password");

    const bootstrapBrokers = [Fn.element(Fn.split(",", mskCluster.bootstrapBrokersSaslScram), 0)];

    let zillaPlusRole;
    if (!userVariables.createZillaPlusRole) {
      const zillaPlusRoleVar = new TerraformVariable(this, "zilla_plus_role_name", {
        type: "string",
        description: "The role name assumed by Zilla Plus instances.",
      });

      zillaPlusRole = zillaPlusRoleVar.stringValue;
    } else {
      const iamRole = new IamRole(this, "zilla_plus_role", {
        name: "zilla_plus_role",
        assumeRolePolicy: JSON.stringify({
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Principal: {
                Service: "ec2.amazonaws.com",
              },
              Action: "sts:AssumeRole",
            },
            {
              Effect: "Allow",
              Principal: {
                Service: "cloudformation.amazonaws.com",
              },
              Action: "sts:AssumeRole",
            },
          ],
        }),
        managedPolicyArns: [
          "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
          "arn:aws:iam::aws:policy/AWSCertificateManagerReadOnly",
          "arn:aws:iam::aws:policy/AWSGlueSchemaRegistryReadonlyAccess",
          "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess",
        ],
        inlinePolicy: [
          {
            name: "ZillaPlusSecretsManagerRead",
            policy: JSON.stringify({
              Version: "2012-10-17",
              Statement: [
                {
                  Sid: "VisualEditor0",
                  Effect: "Allow",
                  Action: [
                    "acm-pca:GetCertificate",
                    "acm-pca:GetCertificateAuthorityCertificate",
                    "acm-pca:DescribeCertificateAuthority",
                    "tag:GetResources",
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:DescribeSecret",
                  ],
                  Resource: ["*"],
                },
              ],
            }),
          },
        ],
      });

      const iamInstanceProfile = new IamInstanceProfile(this, "zilla_plus_instance_profile", {
        name: "zilla_plus_role",
        role: iamRole.name,
      });

      new IamRolePolicy(this, "ZillaPlusRolePolicy", {
        role: iamRole.name,
        policy: JSON.stringify({
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "VisualEditor0",
              Effect: "Allow",
              Action: ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
              Resource: ["arn:aws:secretsmanager:*:*:secret:*"],
            },
          ],
        }),
      });

      zillaPlusRole = iamInstanceProfile.name;
    }

    const publicTcpPort = new TerraformVariable(this, "public_tcp_port", {
      type: "number",
      default: 8883,
      description: "The public port number to be used by MQTT clients",
    });

    let zillaPlusSecurityGroups;

    if (!userVariables.createZillaPlusSecurityGroup) {
      const zillaPlusSecurityGroupsVar = new TerraformVariable(this, "zilla_plus_security_groups", {
        type: "list(string)",
        description: "The security groups associated with Zilla Plus instances.",
      });
      zillaPlusSecurityGroups = zillaPlusSecurityGroupsVar.listValue;
    } else {
      const zillaPlusSG = new SecurityGroup(this, "ZillaPlusSecurityGroup", {
        vpcId: vpc.id,
        description: "Security group for Zilla Plus",
        ingress: [
          {
            fromPort: publicTcpPort.value,
            toPort: publicTcpPort.value,
            protocol: "tcp",
            cidrBlocks: ["0.0.0.0/0"],
          },
        ],
        egress: [
          {
            fromPort: 0,
            toPort: 65535,
            protocol: "tcp",
            cidrBlocks: ["0.0.0.0/0"],
          },
        ],
        tags: {
          Name: "zilla-plus-security-group",
        },
      });
      zillaPlusSecurityGroups = [zillaPlusSG.id];
    }

    const zillaPlusCapacity = new TerraformVariable(this, "zilla_plus_capacity", {
      type: "number",
      default: 2,
      description: "The initial number of Zilla Plus instances",
    });

    const publicTlsCertificateKey = new TerraformVariable(this, "public_tls_certificate_key", {
      type: "string",
      description: "TLS Certificate Private Key Secret ARN",
    });
    // Validate that the Certificate Key exists
    new DataAwsSecretsmanagerSecretVersion(this, "publicTlsCertificate", {
      secretId: publicTlsCertificateKey.stringValue,
    });

    let keyName = "";

    if (userVariables.sshKeyEnabled) {
      const keyNameVar = new TerraformVariable(this, "zilla_plus_ssh_key", {
        type: "string",
        description: "Name of an existing EC2 KeyPair to enable SSH access to the instances",
      });
      keyName = keyNameVar.stringValue;
    }

    const instanceType = new TerraformVariable(this, "zilla_plus_instance_type", {
      type: "string",
      default: "t3.small",
      description: "MSK Proxy EC2 instance type",
    });
    instanceType.addValidation({
      condition: `${Fn.contains(instanceTypes.instanceTypes, instanceType.stringValue)}`,
      errorMessage: "must be a valid EC2 instance type.",
    });

    let zillaTelemetryContent = "";
    let bindingTelemetryContent = "";

    if (!userVariables.cloudwatchDisabled) {
      const defaultLogGroupName = `${id}-group`;
      const defaultMetricNamespace = `${id}-namespace`;

      const cloudWatchLogsGroup = new TerraformVariable(this, "cloudwatch_logs_group", {
        type: "string",
        description: "The Cloud Watch log group Zilla Plush should publish logs",
        default: defaultLogGroupName,
      });

      const cloudWatchMetricsNamespace = new TerraformVariable(this, "cloudwatch_metrics_namespace", {
        type: "string",
        description: "The Cloud Watch metrics namespace Zilla Plush should publish metrics",
        default: defaultMetricNamespace,
      });

      new CloudwatchLogGroup(this, "loggroup", {
        name: cloudWatchLogsGroup.stringValue,
      });

      const logsSection = `
        logs:
          group: ${cloudWatchLogsGroup.stringValue}
          stream: events`;

      const metricsSection = `
        metrics:
          namespace: ${cloudWatchMetricsNamespace.stringValue}`;

      zillaTelemetryContent = `
telemetry:
  metrics:
    - stream.active.received
    - stream.active.sent
    - stream.opens.received
    - stream.opens.sent
    - stream.data.received
    - stream.data.sent
    - stream.errors.received
    - stream.errors.sent
    - stream.closes.received
    - stream.closes.sent
  exporters:
    stdout_logs_exporter:
      type: stdout
    aws0:
      type: aws-cloudwatch
      options:
${logsSection}
${metricsSection}`;

      bindingTelemetryContent = `
    telemetry:
      metrics:
        - stream.*`;
    }

    const ami = new dataAwsAmi.DataAwsAmi(this, "LatestAmi", {
      mostRecent: true,
      filter: [
        {
          name: "product-code",
          values: ["ca5mgk85pjtbyuhtfluzisgzy"],
        },
        {
          name: "is-public",
          values: ["true"],
        },
      ],
      owners: ["679593333241"],
    });

    const nlb = new Lb(this, "NetworkLoadBalancer", {
      name: "network-load-balancer",
      loadBalancerType: "network",
      internal: false,
      subnets: subnetIds,
      securityGroups: zillaPlusSecurityGroups,
      enableCrossZoneLoadBalancing: true,
    });

    const nlbTargetGroup = new LbTargetGroup(this, "NLBTargetGroup", {
      name: "nlb-target-group",
      port: publicTcpPort.value,
      protocol: "TCP",
      vpcId: vpc.id,
    });

    new LbListener(this, "NLBListener", {
      loadBalancerArn: nlb.arn,
      port: publicTcpPort.value,
      protocol: "TCP",
      defaultAction: [
        {
          type: "forward",
          targetGroupArn: nlbTargetGroup.arn,
        },
      ],
    });

    const kafkaSaslUsername = Fn.join("", ["${{aws.secrets.", mskAccessCredentialsName.stringValue, "#username}}"]);

    const kafkaSaslPassword = Fn.join("", ["${{aws.secrets.", mskAccessCredentialsName.stringValue, "#password}}"]);

    const kafkaBootstrapServers = `['${Fn.join(`','`, Fn.split(",", mskCluster.bootstrapBrokersSaslScram))}']`;

    const zillaYamlContent = `
name: public
${zillaTelemetryContent}
vaults:
  secure:
    type: aws
bindings:
  tcp_server:
    type: tcp
    kind: server
${bindingTelemetryContent}
    options:
      host: 0.0.0.0
      port: ${publicTcpPort}
    exit: tls_server
  tls_server:
    type: tls
    kind: server
    vault: secure
${bindingTelemetryContent}
    options:
      keys:
      - ${publicTlsCertificateKey.stringValue}
    exit: mqtt_server
  mqtt_server:
    type: mqtt
    kind: server
${bindingTelemetryContent}
    exit: mqtt_kafka_mapping
  mqtt_kafka_mapping:
    type: mqtt-kafka
    kind: proxy
${bindingTelemetryContent}
    options:
      topics:
        sessions: ${kafkaTopicMqttSessions}
        messages: ${kafkaTopicMqttMessages}
        retained: ${kafkaTopicMqttRetained}
    exit: kafka_cache_client
  kafka_cache_client:
    type: kafka
    kind: cache_client
${bindingTelemetryContent}
    exit: kafka_cache_server
  kafka_cache_server:
    type: kafka
    kind: cache_server
${bindingTelemetryContent}
    options:
      bootstrap:
        - ${kafkaTopicMqttMessages}
        - ${kafkaTopicMqttRetained}
    exit: kafka_client
  kafka_client:
    type: kafka
    kind: client
    options:
      servers: ${kafkaBootstrapServers}
      sasl:
        mechanism: scram-sha-512
        username: '${kafkaSaslUsername}'
        password: '${kafkaSaslPassword}'
${bindingTelemetryContent}
    exit: tls_client
  tls_client:
    type: tls
    kind: client
    vault: secure
${bindingTelemetryContent}
    exit: tcp_client
  tcp_client:
    type: tcp
    kind: client
${bindingTelemetryContent}
`;

    const cfnHupConfContent = `
[main]
stack=${id}
region=${region}
    `;

    const cfnAutoReloaderConfContent = `
[cfn-auto-reloader-hook]
triggers=post.update
path=Resources.MSKProxyLaunchTemplate.Metadata.AWS::CloudFormation::Init
action=/opt/aws/bin/cfn-init -v --stack ${id} --resource ZillaPlusLaunchTemplate --region ${region}
runas=root
    `;

    let kafkaTopicCreationCommand = "";

    if (!userVariables.mqttKafkaTopicCreationDisabled) {
      kafkaTopicCreationCommand = `
wget https://archive.apache.org/dist/kafka/3.5.1/kafka_2.13-3.5.1.tgz
tar -xzf kafka_2.13-3.5.1.tgz
cd kafka_2.13-3.5.1/libs
wget https://github.com/aws/aws-msk-iam-auth/releases/download/v1.1.1/aws-msk-iam-auth-1.1.1-all.jar
cd ../bin
cat <<'END_HELP'> client.properties
sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required username='${username}' password='${password}';
security.protocol=SASL_SSL
sasl.mechanism=SCRAM-SHA-512
END_HELP
./kafka-topics.sh --create --bootstrap-server ${bootstrapBrokers} --command-config client.properties --replication-factor 2 --partitions 3 --topic ${kafkaTopicMqttSessions} --config 'cleanup.policy=compact'
./kafka-topics.sh --create --bootstrap-server ${bootstrapBrokers} --command-config client.properties --replication-factor 2 --partitions 3 --topic ${kafkaTopicMqttRetained} --config 'cleanup.policy=compact'
./kafka-topics.sh --create --bootstrap-server ${bootstrapBrokers} --command-config client.properties --replication-factor 2 --partitions 3 --topic ${kafkaTopicMqttMessages}
      `;
    }

    const userData = `#!/bin/bash -xe
yum update -y aws-cfn-bootstrap
cat <<'END_HELP' > /etc/zilla/zilla.yaml
${zillaYamlContent}
END_HELP

chown ec2-user:ec2-user /etc/zilla/zilla.yaml

mkdir /etc/cfn
cat <<EOF > /etc/cfn/cfn-hup.conf
${cfnHupConfContent}
EOF

chown root:root /etc/cfn/cfn-hup.conf
chmod 0400 /etc/cfn/cfn-hup.conf

mkdir /etc/cfn/hooks.d
cat <<EOF > /etc/cfn/hooks.d/cfn-auto-reloader.conf
${cfnAutoReloaderConfContent}
EOF

chown root:root /etc/cfn/hooks.d/cfn-auto-reloader.conf
chmod 0400 /etc/cfn/hooks.d/cfn-auto-reloader.conf

systemctl enable cfn-hup
systemctl start cfn-hup
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent
systemctl enable zilla-plus
systemctl start zilla-plus

${kafkaTopicCreationCommand}

    `;

    const MSKProxyLaunchTemplate = new launchTemplate.LaunchTemplate(this, "ZillaPlusLaunchTemplate", {
      imageId: ami.imageId,
      instanceType: instanceType.stringValue,
      networkInterfaces: [
        {
          associatePublicIpAddress: "true",
          deviceIndex: 0,
          securityGroups: zillaPlusSecurityGroups,
        },
      ],
      iamInstanceProfile: {
        name: zillaPlusRole,
      },
      keyName: keyName,
      userData: Fn.base64encode(userData),
    });

    new autoscalingGroup.AutoscalingGroup(this, "zillaPlusGroup", {
      vpcZoneIdentifier: subnetIds,
      launchTemplate: {
        id: MSKProxyLaunchTemplate.id,
      },
      minSize: 1,
      maxSize: 5,
      desiredCapacity: zillaPlusCapacity.numberValue,
      targetGroupArns: [nlbTargetGroup.arn],
    });

    new TerraformOutput(this, "NetworkLoadBalancerOutput", {
      description: "Public DNS name of newly created NLB for Public MSK Proxy",
      value: nlb.dnsName,
    });
  }
}

const app = new App();
new ZillaPlusIotAndControlStack(app, "iot-ingest-and-control");
app.synth();
