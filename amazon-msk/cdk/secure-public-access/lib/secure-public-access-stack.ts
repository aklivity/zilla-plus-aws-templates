import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import { aws_logs as logs, aws_elasticloadbalancingv2 as elbv2, aws_autoscaling as autoscaling} from 'aws-cdk-lib';
import { UserVariables } from './variables';
import  * as subnetCalculator from './subnet-calculator';
import Mustache = require("mustache");
import fs =  require("fs");

interface TemplateData {
  name: string;
  useAcm: boolean;
  cloudwatch?: object;
  public?: object;
  mTLS?: boolean;
  externalHost?: string;
  internalHost?: string;
  msk?: object;
}

export class ZillaPlusSecurePublicAccessStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const userVariables = new UserVariables(this, "main");

    const vpcId = this.node.tryGetContext('vpcId');
    const mskBootstrapServers = this.node.tryGetContext('mskBootstrapServers');

    const vpc = ec2.Vpc.fromLookup(this, 'Vpc', { vpcId: vpcId });

    const internetGateway = new ec2.CfnInternetGateway(this, `InternetGateway-${id}`, {
      tags: [{ key: 'Name', value: 'my-igw' }],
    });

    new ec2.CfnVPCGatewayAttachment(this, `VpcGatewayAttachment-${id}`, {
      vpcId: vpcId,
      internetGatewayId: internetGateway.ref,
    });

    const publicRouteTable = new ec2.CfnRouteTable(this, `PublicRouteTable-${id}`, {
      vpcId: vpcId,
      tags: [{ key: 'Name', value: 'public-route-table' }],
    });

    new ec2.CfnRoute(this, `PublicRoute-${id}`, {
      routeTableId: publicRouteTable.ref,
      destinationCidrBlock: '0.0.0.0/0',
      gatewayId: internetGateway.ref,
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

      // Associate the subnet with the provided route table
      new ec2.CfnSubnetRouteTableAssociation(this, `Subnet${i + 1}RouteTableAssociation`, {
        subnetId: subnet.ref,
        routeTableId: publicRouteTable.ref,
      });
    }


    const mskClientAuthentication = userVariables.mskClientAuthentication;

    const domainParts = mskBootstrapServers.split(',')[0].split(':');
    const serverAddress = domainParts[0];
    const mskPort = domainParts[1];

    const addressParts = serverAddress.split('.');
    const mskBootstrapCommonPart = addressParts.slice(1).join(".");
    const mskWildcardDNS = `*.${mskBootstrapCommonPart}`;

    const mTLSEnabled = mskClientAuthentication === 'mTLS';
    const publicTlsCertificateViaAcm = userVariables.publicTlsCertificateViaAcm;

    const data: TemplateData = {
      name: 'public',
      useAcm: publicTlsCertificateViaAcm,
      mTLS: mTLSEnabled,
      public: {}
    };


    if (mTLSEnabled) {
      
      const mskCertificateAuthorityArn = new cdk.CfnParameter(this, 'MskCertificateAuthorityArn', {
        type: 'String',
        description: 'ACM Private Certificate Authority ARN used to authorize clients connecting to the MSK cluster',
      }).valueAsString;

      let publicCertificateAuthority = mskCertificateAuthorityArn;
      if (userVariables.publicCertificateAuthority) {
        const publicCertificateAuthorityArn = new cdk.CfnParameter(
          this,
          'PublicCertificateAuthorityArn',
          {
            type: 'String',
            description:
              'ACM Private Certificate Authority ARN used to authorize clients connecting to the Public Zilla Plus',
            default: mskCertificateAuthorityArn,
          }
        ).valueAsString;

        publicCertificateAuthority = publicCertificateAuthorityArn;
      }
      data.public  = {
        certificateAuthority: publicCertificateAuthority
      }
    }

    const publicTlsCertificateKey = new cdk.CfnParameter(this, 'PublicTlsCertificateKey', {
      type: 'String',
      description: 'TLS Certificate SecretsManager or CertificateManager ARN',
    });

    let zillaPlusRole: string;

    if (!userVariables.createZillaPlusRole) {
      const zillaPlusRoleParam = new cdk.CfnParameter(this, 'ZillaPlusRoleName', {
        type: 'String',
        description: 'The role name assumed by Zilla Plus instances.',
      });

      zillaPlusRole = zillaPlusRoleParam.valueAsString;
    } else {
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
                  'arn:aws:secretsmanager:*:*:secret:wildcard.example.aklivity.io*',
                  'arn:aws:secretsmanager:*:*:secret:client-*',
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
        ],
      });

      if (userVariables.publicTlsCertificateViaAcm) {
        iamPolicy.addStatements(
          new iam.PolicyStatement({
            sid: 's3Statement',
            effect: iam.Effect.ALLOW,
            actions: ['s3:GetObject'],
            resources: ['arn:aws:s3:::*/*'],
          }),
          new iam.PolicyStatement({
            sid: 'kmsDecryptStatement',
            effect: iam.Effect.ALLOW,
            actions: ['kms:Decrypt'],
            resources: ['arn:aws:kms:*:*:key/*'],
          }),
          new iam.PolicyStatement({
            sid: 'getRoleStatement',
            effect: iam.Effect.ALLOW,
            actions: ['iam:GetRole'],
            resources: [`arn:aws:iam::*:role/${iamRole.roleName}`],
          })
        );

        new ec2.CfnEnclaveCertificateIamRoleAssociation(this, `ZillaPlusEnclaveIamRoleAssociation-${id}`, {
          certificateArn: publicTlsCertificateKey.valueAsString,
          roleArn: iamRole.roleArn,
        });
      }

      new iam.CfnPolicy(this, `ZillaPlusRolePolicy-${id}`, {
        policyName: `ZillaPlusRolePolicy-${id}`,
        roles: [iamRole.roleName],
        policyDocument: iamPolicy.toJSON(),
      });

        zillaPlusRole = iamInstanceProfile.ref;
    }

    let zillaPlusSecurityGroups;

    if (!userVariables.createZillaPlusSecurityGroup) {
      const zillaPlusSecurityGroupsParam = new cdk.CfnParameter(this, 'ZillaPlusSecurityGroups', {
        type: 'List<AWS::EC2::SecurityGroup::Id>',
        description: 'The security groups associated with Zilla Plus instances.',
      });
      zillaPlusSecurityGroups = cdk.Fn.split(',', zillaPlusSecurityGroupsParam.valueAsString);
    } else {
      const zillaPlusSG = new ec2.SecurityGroup(this, `ZillaPlusSecurityGroup-${id}`, {
        vpc: vpcId,
        description: 'Security group for Zilla Plus',
        securityGroupName: 'zilla-plus-security-group',
      });

      zillaPlusSG.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcpRange(9092, 9096), 'Allow inbound traffic on Kafka ports');
      zillaPlusSG.addEgressRule(ec2.Peer.anyIpv4(), ec2.Port.allTcp(), 'Allow all outbound TCP traffic');

      zillaPlusSecurityGroups = [zillaPlusSG.securityGroupId];
    }

    const zillaPlusCapacity = new cdk.CfnParameter(this, 'ZillaPlusCapacity', {
      type: 'Number',
      default: 2,
      description: 'The initial number of Zilla Plus instances',
    });

    const publicPort = new cdk.CfnParameter(this, 'PublicPort', {
      type: 'Number',
      default: 9094,
      description: 'The public port number to be used by Kafka clients',
    });

    const publicWildcardDNS = new cdk.CfnParameter(this, 'PublicWildcardDNS', {
      type: 'String',
      description: 'The public wildcard DNS pattern for bootstrap servers to be used by Kafka clients',
    });

    if (!userVariables.publicTlsCertificateViaAcm) {
      cdk.aws_secretsmanager.Secret.fromSecretNameV2(this, 'PublicTlsCertificate', publicTlsCertificateKey.valueAsString);
    }

    let keyName: string = '';
    if (userVariables.sshKeyEnabled) {
      const sshKeyParam = new cdk.CfnParameter(this, 'ZillaPlusSSHKey', {
        type: 'String',
        description: 'Name of an existing EC2 KeyPair to enable SSH access to the instances',
      });
      keyName = sshKeyParam.valueAsString;
    }

    let acmYamlContent = '';
    let enclavesAcmServiceStart = '';

    if (userVariables.publicTlsCertificateViaAcm) {
      acmYamlContent = `
enclave:
  cpu_count: 2
  memory_mib: 256

options:
  sync_interval_secs: 600

tokens:
  - label: acm-token-example
    source:
      Acm:
        certificate_arn: '${publicTlsCertificateKey.valueAsString}'
    refresh_interval_secs: 43200
    pin: 1234
`;
      enclavesAcmServiceStart = `
systemctl enable nitro-enclaves-acm.service
systemctl start nitro-enclaves-acm.service
`;
    }

    // CloudWatch Logs and Metrics
    if (!userVariables.cloudwatchDisabled) {
      const defaultLogGroupName = `${id}-group`;
      const defaultMetricNamespace = `${id}-namespace`;

      const cloudWatchLogGroup = new logs.LogGroup(this, `LogGroup-${id}`, {
        logGroupName: defaultLogGroupName,
        retention: logs.RetentionDays.ONE_MONTH,
      });

      const cloudWatchMetricsNamespace = defaultMetricNamespace;

      const dataCloudwatch = {
        logs: {
          group: cloudWatchLogGroup.logGroupName,
        },
        metrics: {
          namespace: cloudWatchMetricsNamespace,
        },
      };
    }

    // Instance Type Parameter
    const instanceType = new cdk.CfnParameter(this, 'ZillaPlusInstanceType', {
      type: 'String',
      default: userVariables.publicTlsCertificateViaAcm ? 'c6i.xlarge' : 't3.small',
      description: 'Zilla Plus EC2 instance type',
    });

    // EC2 Image ID (AMI)
    let imageId = userVariables.zillaPlusAmi;
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

    const nlb = new elbv2.CfnLoadBalancer(this, `NetworkLoadBalancer-${id}`, {
      name: `nlb-${id}`,
      scheme: 'internet-facing',
      subnets: subnetIds,
      type: 'network',
      ipAddressType: 'ipv4',
    });

    const nlbTargetGroup = new elbv2.CfnTargetGroup(this, `NLBTargetGroup-${id}`, {
      name: `nlb-tg-${id}`,
      port: Number(instanceType.default || 9094),
      protocol: 'TCP',
      vpcId: vpcId,
    });

    new elbv2.CfnListener(this, `NLBListener-${id}`, {
      loadBalancerArn: nlb.ref,
      port: Number(instanceType.default || 9094),
      protocol: 'TCP',
      defaultActions: [
        {
          type: 'forward',
          targetGroupArn: nlbTargetGroup.ref,
        },
      ],
    });

    const externalHost = ["b-#.", cdk.Fn.select(1, cdk.Fn.split("*.", publicWildcardDNS.valueAsString))].join("");
    const internalHost = ["b-#.", cdk.Fn.select(1, cdk.Fn.split("*.", mskWildcardDNS))].join("");

    data.public = {
      ...data.public,
      port: publicPort.value,
      tlsCertificateKey: publicTlsCertificateKey.valueAsString,
      wildcardDNS: publicWildcardDNS.valueAsString
    }
    data.externalHost = externalHost;
    data.internalHost = internalHost;
    data.msk = {
      port: mskPort,
      wildcardDNS: mskWildcardDNS
    };

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

    const userData = `#!/bin/bash -xe
yum update -y aws-cfn-bootstrap
cat <<EOF > /etc/zilla/zilla.yaml
${renderedYaml}
EOF

cat <<EOF > /etc/nitro_enclaves/acm.yaml
${acmYamlContent}
EOF

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
${enclavesAcmServiceStart}
systemctl enable zilla-plus
systemctl start zilla-plus

    `;
    
    const zillaPlusLaunchTemplate = new ec2.CfnLaunchTemplate(this, `ZillaPlusLaunchTemplate-${id}`, {
      launchTemplateData: {
        imageId: imageId,
        instanceType: instanceType.valueAsString,
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
        enclaveOptions: {
          enabled: publicTlsCertificateViaAcm,
        },
        keyName: keyName,
        userData: cdk.Fn.base64(userData)
      },
    });

    new autoscaling.CfnAutoScalingGroup(this, `ZillaPlusGroup-${id}`, {
      vpcZoneIdentifier: subnetIds,
      launchTemplate: {
        launchTemplateId: zillaPlusLaunchTemplate.ref,
        version: ''
      },
      minSize: '1',
      maxSize: '5',
      desiredCapacity: zillaPlusCapacity.valueAsString,
      targetGroupArns: [nlbTargetGroup.ref]
    });

    new cdk.CfnOutput(this, 'NetworkLoadBalancerOutput', 
    { 
      description: "Public DNS name of newly created NLB for Zilla Plus",
      value: nlb.attrDnsName 
    });
  }
}
