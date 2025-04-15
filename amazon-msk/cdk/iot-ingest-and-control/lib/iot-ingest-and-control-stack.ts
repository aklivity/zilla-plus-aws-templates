import * as cdk from 'aws-cdk-lib';
import { Construct, Node } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import { aws_logs as logs, aws_elasticloadbalancingv2 as elbv2, aws_autoscaling as autoscaling} from 'aws-cdk-lib';
import  * as subnetCalculator from './subnet-calculator';
import Mustache = require("mustache");
import fs =  require("fs");

interface TemplateData {
  name: string;
  cloudwatch?: object;
  public?: object;
  topics?: object;
  kafka?: object;
}


export class IotIngestAndControlStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const mandatoryVariables = [
      'vpcId',
      'msk',
      'public'
    ];
    
    function validateContextKeys(node: object, keys: string[]): void {
      const missingKeys = [];
      if (node instanceof Node) {
        missingKeys.push(...keys.filter((key) => !node.tryGetContext(key)));
      } else if (typeof node === 'object' && node !== null) {
        missingKeys.push(...keys.filter((key) => !(key in node)));
      } else {
        throw new Error(`Invalid node type. Must be either a constructs.Node or a JSON object.`);
      }
      if (missingKeys.length > 0) {
        throw new Error(`Missing required context variables: ${missingKeys.join(', ')}`);
      }
    }

    const zillaPlusContext = this.node.tryGetContext('zilla-plus');
    validateContextKeys(zillaPlusContext, mandatoryVariables);
    const vpcId = zillaPlusContext.vpcId;
    const msk = zillaPlusContext.msk;
    const mandatoryMSKVariables = [
      'servers',
      'credentials'
    ];
    validateContextKeys(msk, mandatoryMSKVariables);
    const mskBootstrapServers = msk.servers;
    const mskCredentialsSecretName = msk.credentials;

    const publicVar = zillaPlusContext.public;
    const mandatoryPublicVariables = [
      'certificate',
    ];
    validateContextKeys(publicVar, mandatoryPublicVariables);
    const publicTlsCertificateKey = publicVar.certificate;

    const topics = zillaPlusContext.topics;
    const kafkaTopicMqttSessions = topics?.sessions ?? "mqtt-sessions";
    const kafkaTopicMqttRetained = topics?.retained ?? "mqtt-retained";
    const kafkaTopicMqttMessages = topics?.messages ?? "mqtt-messages";


    const vpc = ec2.Vpc.fromLookup(this, 'Vpc', { vpcId: vpcId });
    const subnets = vpc.selectSubnets();
    if (subnets.isPendingLookup) {
      // return before using the vpc, the cdk will rerun immediately after the lookup
      return;
    }

    let igwId = zillaPlusContext.igwId;;
    if (!igwId)
    {
      const internetGateway = new ec2.CfnInternetGateway(this, `InternetGateway-${id}`, {
        tags: [{ key: 'Name', value: 'my-igw' }],
      });
      igwId = internetGateway.ref;

      new ec2.CfnVPCGatewayAttachment(this, `VpcGatewayAttachment-${id}`, {
        vpcId: vpcId,
        internetGatewayId: igwId,
      });
    }


    const publicRouteTable = new ec2.CfnRouteTable(this, `PublicRouteTable-${id}`, {
      vpcId: vpcId,
      tags: [{ key: 'Name', value: 'public-route-table' }],
    });

    new ec2.CfnRoute(this, `PublicRoute-${id}`, {
      routeTableId: publicRouteTable.ref,
      destinationCidrBlock: '0.0.0.0/0',
      gatewayId: igwId,
    });

    const existingSubnets = vpc.isolatedSubnets.concat(vpc.publicSubnets, vpc.privateSubnets);
    const existingCidrBlocks = existingSubnets.map((subnet) => subnet.ipv4CidrBlock);

    const availableCidrBlocks = subnetCalculator.findAvailableCidrBlocks(
      vpc.vpcCidrBlock,
      existingCidrBlocks,
      2);

    const availabilityZones = cdk.Fn.getAzs();
    const subnetIds: string[] = [];

    for (let i = 0; i < 2; i++) {
      const az = cdk.Fn.select(i, availabilityZones);
      const cidrBlock = cdk.Fn.select(i, availableCidrBlocks);

      const subnet = new ec2.CfnSubnet(this, `Subnet${i + 1}`, {
        vpcId: vpcId,
        cidrBlock: cidrBlock,
        availabilityZone: az,
        mapPublicIpOnLaunch: true,
        tags: [
          {
            key: 'Name',
            value: `public-subnet-${i + 1}-${id}`,
          },
        ],
      });

      subnetIds.push(subnet.ref);

      new ec2.CfnSubnetRouteTableAssociation(this, `Subnet${i + 1}RouteTableAssociation`, {
        subnetId: subnet.ref,
        routeTableId: publicRouteTable.ref,
      });
    }

    let zillaPlusRole = zillaPlusContext.roleName;

    if (!zillaPlusRole) {
      const iamRole = new iam.Role(this, `ZillaPlusRole-${id}`, {
        roleName: `zilla_plus_role-${id}`,
        assumedBy: new iam.CompositePrincipal(
          new iam.ServicePrincipal('ec2.amazonaws.com'),
          new iam.ServicePrincipal('cloudformation.amazonaws.com')
        ),
        managedPolicies: [
          iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
          iam.ManagedPolicy.fromAwsManagedPolicyName('AWSCertificateManagerReadOnly'),
          iam.ManagedPolicy.fromAwsManagedPolicyName('AWSGlueSchemaRegistryReadonlyAccess'),
          iam.ManagedPolicy.fromAwsManagedPolicyName('CloudWatchLogsFullAccess'),
        ],
        inlinePolicies: {
          CCProxySecretsManagerRead: new iam.PolicyDocument({
            statements: [
              new iam.PolicyStatement({
                sid: 'VisualEditor0',
                effect: iam.Effect.ALLOW,
                actions: [
                  'acm-pca:GetCertificate',
                  'acm-pca:GetCertificateAuthorityCertificate',
                  'acm-pca:DescribeCertificateAuthority',
                  'tag:GetResources',
                  'secretsmanager:GetSecretValue',
                  'secretsmanager:DescribeSecret',
                ],
                resources: [
                  '*',
                ],
              }),
            ],
          }),
        },
      });

      const iamInstanceProfile = new iam.CfnInstanceProfile(this, `ZillaPlusInstanceProfile-${id}`, {
        instanceProfileName: `zilla_plus_role-${id}`,
        roles: [iamRole.roleName],
      });

      const iamPolicy = new iam.PolicyDocument({
        statements: [
          new iam.PolicyStatement({
            sid: 'secretStatement',
            effect: iam.Effect.ALLOW,
            actions: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'],
            resources: ['arn:aws:secretsmanager:*:*:secret:*'],
          }),
          new iam.PolicyStatement({
            sid: 'cloudwatchStatement',
            effect: iam.Effect.ALLOW,
            actions: ['logs:*', 'cloudwatch:GenerateQuery', 'cloudwatch:PutMetricData'],
            resources: ['*'],
          }),
        ],
      });

      new iam.CfnPolicy(this, `ZillaPlusRolePolicy-${id}`, {
        policyName: `ZillaPlusRolePolicy-${id}`,
        roles: [iamRole.roleName],
        policyDocument: iamPolicy.toJSON(),
      });

        zillaPlusRole = iamInstanceProfile.ref;
    }

    const publicPort = publicVar.port ?? 8883;

    let zillaPlusSecurityGroups = zillaPlusContext.securityGroups;

    if (zillaPlusSecurityGroups) {
      zillaPlusSecurityGroups = zillaPlusSecurityGroups.split(',');
    } else {
      const zillaPlusSG = new ec2.SecurityGroup(this, `ZillaPlusSecurityGroup-${id}`, {
        vpc: vpc,
        description: 'Security group for Zilla Plus',
        securityGroupName: `zilla-plus-security-group-${id}`,
      });

      zillaPlusSG.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(publicPort));
      zillaPlusSG.addEgressRule(ec2.Peer.anyIpv4(), ec2.Port.allTcp());

      zillaPlusSecurityGroups = [zillaPlusSG.securityGroupId];
    }

    const zillaPlusCapacity = zillaPlusContext.capacity ?? 2;
    const keyName = zillaPlusContext.sshKey;
    const instanceType = zillaPlusContext.instanceType ?? 't3.small';

    let imageId =  zillaPlusContext.ami;
    if (!imageId) {
      const ami = ec2.MachineImage.lookup({
        name: 'Aklivity Zilla Plus *',
        filters: {
          'product-code': ['ca5mgk85pjtbyuhtfluzisgzy'],
          'is-public': ['true'],
        },
      });
      imageId = ami.getImage(this).imageId;
    }

    const data: TemplateData = {
      name: 'iot',
    }

    const cloudwatch = zillaPlusContext.cloudwatch;
    const cloudwatchDisabled = cloudwatch?.disabled ?? false;

    if (!cloudwatchDisabled) {
      const defaultLogGroupName = `${id}-group`;
      const defaultMetricNamespace = `${id}-namespace`;

      const logGroupName = cloudwatch?.logs?.group ?? defaultLogGroupName;
      const metricNamespace = cloudwatch?.metrics?.namespace ?? defaultMetricNamespace;

      const cloudWatchLogGroup = new logs.LogGroup(this, `LogGroup-${id}`, {
        logGroupName: logGroupName,
        retention: logs.RetentionDays.ONE_MONTH,
      });

      new logs.LogStream(this, `LogStream-${id}`, {
        logGroup: cloudWatchLogGroup,
        logStreamName: 'events',
      });

      data.cloudwatch = {
        logs: {
          group: cloudWatchLogGroup.logGroupName,
        },
        metrics: {
          namespace: metricNamespace,
        },
      };
    }

    const nlb = new elbv2.CfnLoadBalancer(this, `NetworkLoadBalancer-${id}`, {
      name: `nlb-${id}`,
      scheme: 'internet-facing',
      subnets: subnetIds,
      type: 'network',
      ipAddressType: 'ipv4',
    });

    const nlbTargetGroup = new elbv2.CfnTargetGroup(this, `NLBTargetGroup-${id}`, {
      name: `nlb-tg-${id}`,
      port: publicPort,
      protocol: 'TCP',
      vpcId: vpcId,
    });

    new elbv2.CfnListener(this, `NLBListener-${id}`, {
      loadBalancerArn: nlb.ref,
      port: publicPort,
      protocol: 'TCP',
      defaultActions: [
        {
          type: 'forward',
          targetGroupArn: nlbTargetGroup.ref,
        },
      ],
    });
    
    const kafkaSaslUsername = `\${{aws.secrets.${mskCredentialsSecretName}#username}}`;
    const kafkaSaslPassword = `\${{aws.secrets.${mskCredentialsSecretName}#password}}`;
    const kafkaBootstrapServers = `['${mskBootstrapServers.split(",").join("','")}']`;

    data.kafka = {
      servers: kafkaBootstrapServers,
      sasl : {
        username: kafkaSaslUsername,
        password: kafkaSaslPassword
      }
    }
    data.public = {
      port: publicPort,
      tlsCertificateKey: publicTlsCertificateKey
    }
    data.topics = {
      sessions: kafkaTopicMqttSessions,
      messages: kafkaTopicMqttMessages,
      retained: kafkaTopicMqttRetained
    };

    const kafkaTopicCreationDisabled = zillaPlusContext.kafkaTopicCreationDisabled ?? false;

    const yamlTemplate: string = fs.readFileSync('zilla.yaml.mustache', 'utf8');
    const renderedYaml: string = Mustache.render(yamlTemplate, data);

    const cfnHupConfContent = `
[main]
stack=${id}
region=${this.region}
    `;

    const cfnAutoReloaderConfContent = `
[cfn-auto-reloader-hook]
triggers=post.update
path=Resources.ZillaPlusLaunchTemplate.Metadata.AWS::CloudFormation::Init
action=/opt/aws/bin/cfn-init -v --stack ${id} --resource ZillaPlusLaunchTemplate --region ${this.region}
runas=root
    `;

    let kafkaTopicCreationCommand = "";

    if (!kafkaTopicCreationDisabled) {
      kafkaTopicCreationCommand = `
wget https://archive.apache.org/dist/kafka/3.5.1/kafka_2.13-3.5.1.tgz
tar -xzf kafka_2.13-3.5.1.tgz
cd kafka_2.13-3.5.1/libs
wget https://github.com/aws/aws-msk-iam-auth/releases/download/v1.1.1/aws-msk-iam-auth-1.1.1-all.jar
cd ../bin
SECRET_STRING=$(aws secretsmanager get-secret-value --secret-id ${mskCredentialsSecretName} --query SecretString --output text)
USERNAME=$(echo $SECRET_STRING | jq -r '.username')
PASSWORD=$(echo $SECRET_STRING | jq -r '.password')

cat <<EOF> client.properties
sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required username=$USERNAME password=$PASSWORD;
security.protocol=SASL_SSL
sasl.mechanism=SCRAM-SHA-512
EOF
./kafka-topics.sh --create --bootstrap-server ${mskBootstrapServers} --command-config client.properties --replication-factor 2 --partitions 3 --topic ${kafkaTopicMqttSessions} --config 'cleanup.policy=compact'
./kafka-topics.sh --create --bootstrap-server ${mskBootstrapServers} --command-config client.properties --replication-factor 2 --partitions 3 --topic ${kafkaTopicMqttRetained} --config 'cleanup.policy=compact'
./kafka-topics.sh --create --bootstrap-server ${mskBootstrapServers} --command-config client.properties --replication-factor 2 --partitions 3 --topic ${kafkaTopicMqttMessages}

      `;
    }

    const userData = `#!/bin/bash -xe
yum update -y aws-cfn-bootstrap
cat <<'END_HELP' > /etc/zilla/zilla.yaml
${renderedYaml}
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

    const zillaPlusLaunchTemplate = new ec2.CfnLaunchTemplate(this, `ZillaPlusLaunchTemplate-${id}`, {
      launchTemplateData: {
        imageId: imageId,
        instanceType: instanceType,
        networkInterfaces: [
          {
            associatePublicIpAddress: true,
            deviceIndex: 0,
            groups: zillaPlusSecurityGroups,
          },
        ],
        iamInstanceProfile: {
          name: zillaPlusRole,
        },
        keyName: keyName,
        userData: cdk.Fn.base64(userData)
      },
    });

    new autoscaling.CfnAutoScalingGroup(this, `ZillaPlusGroup-${id}`, {
      vpcZoneIdentifier: subnetIds,
      launchTemplate: {
        launchTemplateId: zillaPlusLaunchTemplate.ref,
        version: '1'
      },
      minSize: '1',
      maxSize: '5',
      desiredCapacity: zillaPlusCapacity.toString(),
      targetGroupArns: [nlbTargetGroup.ref]
    });

    new cdk.CfnOutput(this, 'NetworkLoadBalancerOutput', 
    { 
      description: "Public DNS name of newly created NLB for Zilla Plus",
      value: nlb.attrDnsName 
    });

  }
}
