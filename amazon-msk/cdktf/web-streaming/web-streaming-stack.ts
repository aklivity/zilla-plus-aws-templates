import { Construct, Node } from "constructs";
import { TerraformStack, TerraformOutput, Fn, Op } from "cdktf";
import { AwsProvider } from "@cdktf/provider-aws/lib/provider";
import { Lb } from "@cdktf/provider-aws/lib/lb";
import { LbListener } from "@cdktf/provider-aws/lib/lb-listener";
import { dataAwsAmi, launchTemplate } from "@cdktf/provider-aws";
import { autoscalingGroup } from "@cdktf/provider-aws";
import { LbTargetGroup } from "@cdktf/provider-aws/lib/lb-target-group";
import { DataAwsSecretsmanagerSecretVersion } from "@cdktf/provider-aws/lib/data-aws-secretsmanager-secret-version";
import { CloudwatchLogGroup } from "@cdktf/provider-aws/lib/cloudwatch-log-group";
import { DataAwsMskCluster } from "@cdktf/provider-aws/lib/data-aws-msk-cluster";
import { DataAwsAvailabilityZones } from "@cdktf/provider-aws/lib/data-aws-availability-zones";
import { DataAwsMskBrokerNodes } from "@cdktf/provider-aws/lib/data-aws-msk-broker-nodes";
import { DataAwsRegion } from "@cdktf/provider-aws/lib/data-aws-region";
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
import Mustache = require("mustache");
import fs =  require("fs");
import { DataAwsInternetGateway } from "@cdktf/provider-aws/lib/data-aws-internet-gateway";
import { CloudwatchLogStream } from "@cdktf/provider-aws/lib/cloudwatch-log-stream";

interface TemplateData {
  name: string;
  glue?: object;
  cloudwatch?: object;
  mappings?: Array<object>;
  public?: object;
  kafka?: object;
  jwt?: object;
}

function validateContextKeys(node: object, keys: string[]): void {
  const missingKeys = [];
  if (node instanceof Node) {
    missingKeys.push(...keys.filter((key) => !node.tryGetContext(key)));
  } else if (typeof node === 'object' && node !== null) {
    missingKeys.push(...keys.filter((key) => !(key in node)));
  } else {
    var err =new Error(`Invalid node type. Must be either a constructs.Node or a JSON object.`);
    throw err;
  }
  if (missingKeys.length > 0) {
    throw new Error(`Missing required context variables: ${missingKeys.join(', ')}`);
  }
}

export class ZillaPlusWebStreamingStack extends TerraformStack {
  constructor(scope: Construct, id: string) {
    super(scope, id);

    const awsProvider = new AwsProvider(this, "AWS", {});

    const region = new DataAwsRegion(this, "CurrentRegion", {
      provider: awsProvider,
    });

    const mandatoryVariables = [
      'msk',
      'public',
      'mappings',
    ];

    const zillaPlusContext = this.node.tryGetContext('zilla-plus');
    validateContextKeys(zillaPlusContext, mandatoryVariables);
    const msk = zillaPlusContext.msk;
    const mandatoryMSKVariables = [
      'cluster',
      'credentials'
    ];

    validateContextKeys(msk, mandatoryMSKVariables);
    const mskClusterName = msk.cluster;
    const mskCredentialsSecretName = msk.credentials;

    const publicVar = zillaPlusContext.public;
    const mandatoryPublicVariables = [
      'certificate',
    ];
    validateContextKeys(publicVar, mandatoryPublicVariables);

    const publicTlsCertificateKey = publicVar.certificate;
    const mappings = zillaPlusContext.mappings;

    mappings.forEach((mapping: { path: string; topic: string; }) => {
      if (!mapping.path) {
        mapping.path = `/${mapping.topic}`;
      }
    });

    const kafkaTopics: string[] = mappings.map((mapping: { topic: any; }) => mapping.topic);

    const mskCluster = new DataAwsMskCluster(this, "MSKCluster", {
      clusterName: mskClusterName,
    });
    // Validate that the Credentials exists
    new DataAwsSecretsmanagerSecretVersion(this, "mskAccessCredentials", {
      secretId: mskCredentialsSecretName,
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
        {
          name: "mapPublicIpOnLaunch",
          values: ["true"]
        },
      ],
    });

    let igwId = zillaPlusContext.igwId;;
    if (!igwId)
    {
      const igw = new InternetGateway(this, `InternetGateway-${id}`, {
        vpcId: vpc.id,
        tags: {
          Name: "my-igw",
        },
      });
      igwId = igw.id;
    }
    else
    {
      const existingIgw = new DataAwsInternetGateway(this, `ExistingInternetGateway-${id}`, {
        filter: [
          {
            name: "attachment.vpc-id",
            values: [vpc.id],
          },
        ],
      });
      igwId = existingIgw.id;
    }

    const publicRouteTable = new RouteTable(this, `PublicRouteTable-${id}`, {
      vpcId: vpc.id,
      tags: {
        Name: `public-route-table-${id}`,
      }
    });

    new Route(this, `PublicRoute-${id}`, {
      routeTableId: publicRouteTable.id,
      destinationCidrBlock: "0.0.0.0/0",
      gatewayId: igwId
    });

    const availabilityZones = new DataAwsAvailabilityZones(this, "AZs", {});
    const subnetOffset = Fn.lengthOf(subnets.ids);
    const subnetMask = Fn.parseint(Fn.element(Fn.split("/", vpc.cidrBlock), 1), 10);
    const availableIpv4 = subnet.availableIpAddressCount;
    // Math magic to find next power of 2 and based on that the subnetAddressPower
    const subnetAddressPower = Fn.log(Fn.pow(2, Fn.ceil(Fn.log(availableIpv4, 2))), 2);
    const subnetsMax = Op.sub(32, Op.add(subnetAddressPower, subnetMask));

    const subnetIds = [];
    for (let i = 1; i < 3; i++) {
      const az = Fn.element(availabilityZones.names, i);
      const subnetIndex = Op.add(subnetOffset, i);
      const cidrBlock = Fn.cidrsubnet(vpc.cidrBlock, subnetsMax, Op.add(subnetIndex, i));

      const subnet = new Subnet(this, `PublicSubnet${i}-${id}`, {
        vpcId: vpc.id,
        cidrBlock: cidrBlock,
        availabilityZone: az,
        mapPublicIpOnLaunch: true,
        tags: {
          Name: `public-subnet-${subnetIndex + 1}-${id}`,
        },
      });

      subnetIds.push(subnet.id);

      new RouteTableAssociation(this, `PublicSubnet${i}RouteTableAssociation-${id}`, {
        subnetId: subnet.id,
        routeTableId: publicRouteTable.id,
      });
    }

    const bootstrapBrokers = [Fn.element(Fn.split(",", mskCluster.bootstrapBrokersSaslScram), 0)];

    let zillaPlusRole = zillaPlusContext.roleName;

    if (!zillaPlusRole) {
      const iamRole = new IamRole(this, `zilla_plus_role-${id}`, {
        name: `zilla_plus_role-${id}`,
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

      const iamInstanceProfile = new IamInstanceProfile(this, `zilla_plus_instance_profile-${id}`, {
        name: `zilla_plus_role-${id}`,
        role: iamRole.name,
      });

      new IamRolePolicy(this, `ZillaPlusRolePolicy-${id}`, {
        role: iamRole.name,
        policy: JSON.stringify({
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "secretStatement",
              Effect: "Allow",
              Action: ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
              Resource: ["arn:aws:secretsmanager:*:*:secret:*"],
            },
            {
              Sid: "cloudwatchStatement",
              Effect: "Allow",
              Action: ['logs:*', 'cloudwatch:GenerateQuery', 'cloudwatch:PutMetricData'],
              Resource: ["*"],
            }
          ],
        }),
      });

      zillaPlusRole = iamInstanceProfile.name;
    }

    const publicPort = publicVar.port ?? 7143;

    let zillaPlusSecurityGroups = zillaPlusContext.securityGroups;

    if (zillaPlusSecurityGroups) {
      zillaPlusSecurityGroups = zillaPlusSecurityGroups.split(',');
    } else {
      const zillaPlusSG = new SecurityGroup(this, `ZillaPlusSecurityGroup-${id}`, {
        vpcId: vpc.id,
        description: "Security group for Zilla Plus",
        ingress: [
          {
            fromPort: publicPort,
            toPort: publicPort,
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

    const zillaPlusCapacity = zillaPlusContext.capacity ?? 2;
    const keyName = zillaPlusContext.sshKey;
    const instanceType = zillaPlusContext.instanceType ?? 't3.small';

    // Validate that the Certificate Key exists
    new DataAwsSecretsmanagerSecretVersion(this, "publicTlsCertificate", {
      secretId: publicTlsCertificateKey,
    });

    const data: TemplateData = {
      name: 'web',
    }

    const jwt = zillaPlusContext.jwt;
    if (jwt)
    {
      const mandatoryJWTVariables = [
        'issuer',
        'audience',
        'keysUrl'
      ];
      validateContextKeys(jwt, mandatoryJWTVariables);
      const issuer = jwt.issuer;
      const audience = jwt.audience;
      const keysUrl = jwt.keysUrl;

      data.jwt = {
        issuer: issuer,
        audience: audience,
        keysUrl: keysUrl
      }
    }


    const cloudwatch = zillaPlusContext.cloudwatch;
    const cloudwatchDisabled = cloudwatch?.disabled ?? false;

    if (!cloudwatchDisabled) {
      const defaultLogGroupName = `${id}-group`;
      const defaultMetricNamespace = `${id}-namespace`;

      const logGroupName = cloudwatch?.logs?.group ?? defaultLogGroupName;
      const metricNamespace = cloudwatch?.metrics?.namespace ?? defaultMetricNamespace;



      const cloudWatchLogGroup = new CloudwatchLogGroup(this, `loggroup-${id}`, {
        name: logGroupName
      });

      new CloudwatchLogStream(this, `LogStream-${id}`, {
        logGroupName: cloudWatchLogGroup.name,
        name: 'events'
      });

      data.cloudwatch = {
        logs: {
          group: logGroupName
        },
        metrics: {
          namespace: metricNamespace
        },
      };
    }

    const glueRegistry = zillaPlusContext.glueRegistry;
    if (glueRegistry) {
      data.glue = {
        registry: glueRegistry
      }
    }

    let imageId =  zillaPlusContext.ami;
    if (!imageId) {
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
        ]
      });
      imageId = ami.imageId;
    }

    const nlb = new Lb(this, `NetworkLoadBalancer-${id}`, {
      name: `nlb-${id}`,
      loadBalancerType: "network",
      internal: false,
      subnets: subnetIds,
      securityGroups: zillaPlusSecurityGroups,
      enableCrossZoneLoadBalancing: true,
    });

    const nlbTargetGroup = new LbTargetGroup(this, `NLBTargetGroup-${id}`, {
      name: `nlb-tg-${id}`,
      port: publicPort,
      protocol: "TCP",
      vpcId: vpc.id,
    });

    new LbListener(this, `NLBListener-${id}`, {
      loadBalancerArn: nlb.arn,
      port: publicPort,
      protocol: "TCP",
      defaultAction: [
        {
          type: "forward",
          targetGroupArn: nlbTargetGroup.arn,
        },
      ],
    });
    const kafkaSaslUsername = `\${{aws.secrets.${mskCredentialsSecretName}#username}}`;
    const kafkaSaslPassword = `\${{aws.secrets.${mskCredentialsSecretName}#password}}`;
    const kafkaBootstrapServers = `['${Fn.join(`','`, Fn.split(",", mskCluster.bootstrapBrokersSaslScram))}']`;

    data.kafka = {
      servers: kafkaBootstrapServers,
      sasl : {
        username: kafkaSaslUsername,
        password: kafkaSaslPassword
      }
    }
    data.public = {
      port: publicPort,
      certificate: publicTlsCertificateKey
    }
    data.mappings = mappings;

    const kafkaTopicCreationDisabled = zillaPlusContext.kafkaTopicCreationDisabled ?? false;

    const yamlTemplate: string = fs.readFileSync('zilla.yaml.mustache', 'utf8');
    const renderedYaml: string = Mustache.render(yamlTemplate, data);

    const cfnHupConfContent = `
[main]
stack=${id}
region=${region}
    `;

    const cfnAutoReloaderConfContent = `
[cfn-auto-reloader-hook]
triggers=post.update
path=Resources.ZillaPlusLaunchTemplate.Metadata.AWS::CloudFormation::Init
action=/opt/aws/bin/cfn-init -v --stack ${id} --resource ZillaPlusLaunchTemplate --region ${region}
runas=root
    `;

    let topicsCommand = "";
    kafkaTopics.forEach((t: String) => {
      topicsCommand = topicsCommand.concat(`
./kafka-topics.sh --create --if-not-exists --bootstrap-server ${bootstrapBrokers} --command-config client.properties --replication-factor 2 --partitions 3 --topic ${t} --config 'cleanup.policy=compact'`);
    });

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
${topicsCommand}
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

    const ZillaPlusLaunchTemplate = new launchTemplate.LaunchTemplate(this, `ZillaPlusLaunchTemplate-${id}`, {
      imageId: imageId,
      instanceType: instanceType,
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

    new autoscalingGroup.AutoscalingGroup(this, `ZillaPlusGroup-${id}`, {
      vpcZoneIdentifier: subnetIds,
      launchTemplate: {
        id: ZillaPlusLaunchTemplate.id,
      },
      minSize: 1,
      maxSize: 5,
      desiredCapacity: zillaPlusCapacity,
      targetGroupArns: [nlbTargetGroup.arn],
    });

    new TerraformOutput(this, "NetworkLoadBalancerOutput", {
      description: "Public DNS name of newly created NLB for Public MSK Proxy",
      value: nlb.dnsName,
    });
  }
}
