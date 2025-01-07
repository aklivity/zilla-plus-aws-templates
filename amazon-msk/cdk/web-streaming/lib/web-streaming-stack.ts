import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import { aws_logs as logs, aws_elasticloadbalancingv2 as elbv2, aws_autoscaling as autoscaling} from 'aws-cdk-lib';
import  * as subnetCalculator from './subnet-calculator';
import Mustache = require("mustache");
import fs =  require("fs");

interface TemplateData {
  name: string;
  glue?: object;
  cloudwatch?: object;
  path?: string;
  topic?: string;
  public?: object;
  kafka?: object;
  jwt?: object;
}


export class WebStreamingStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const mandatoryVariables = [
      'vpcId',
      'mskBootstrapServers',
      'mskCredentialsSecretName',
      'publicTlsCertificateKey',
      'kafkaTopic',
    ];
    
    function validateContextKeys(node: import('constructs').Node, keys: string[]): void {
      const missingKeys = keys.filter((key) => !node.tryGetContext(key));
      if (missingKeys.length > 0) {
        throw new Error(`Missing required context variables: ${missingKeys.join(', ')}`);
      }
    }
    
    validateContextKeys(this.node, mandatoryVariables);

    const vpcId = this.node.tryGetContext('vpcId');
    const mskBootstrapServers = this.node.tryGetContext('mskBootstrapServers');
    const mskCredentialsSecretName = this.node.tryGetContext('mskCredentialsSecretName');
    const publicTlsCertificateKey = this.node.tryGetContext('publicTlsCertificateKey');
    const kafkaTopic = this.node.tryGetContext('kafkaTopic');

    const customPath = this.node.tryGetContext('customPath');
    const path = customPath ?? `/${kafkaTopic}`;

    const vpc = ec2.Vpc.fromLookup(this, 'Vpc', { vpcId: vpcId });
    const subnets = vpc.selectSubnets();
    if (subnets.isPendingLookup) {
      // return before using the vpc, the cdk will rerun immediately after the lookup
      return;
    }

    let igwId = this.node.tryGetContext('igwId');;
    if (!igwId)
    {
      const internetGateway = new ec2.CfnInternetGateway(this, `InternetGateway-${id}`, {
        tags: [{ key: 'Name', value: 'my-igw' }],
      });
      igwId = internetGateway.ref;
    }


    new ec2.CfnVPCGatewayAttachment(this, `VpcGatewayAttachment-${id}`, {
      vpcId: vpcId,
      internetGatewayId: igwId,
    });

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

    let zillaPlusRole = this.node.tryGetContext('zillaPlusRoleName');

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

    let zillaPlusSecurityGroups = this.node.tryGetContext('zillaPlusSecurityGroups');

    if (zillaPlusSecurityGroups) {
      zillaPlusSecurityGroups = zillaPlusSecurityGroups.split(',');
    } else {
      const zillaPlusSG = new ec2.SecurityGroup(this, `ZillaPlusSecurityGroup-${id}`, {
        vpc: vpc,
        description: 'Security group for Zilla Plus',
        securityGroupName: 'zilla-plus-security-group',
      });

      zillaPlusSG.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcpRange(9092, 9096), 'Allow inbound traffic on Kafka ports');
      zillaPlusSG.addEgressRule(ec2.Peer.anyIpv4(), ec2.Port.allTcp(), 'Allow all outbound TCP traffic');

      zillaPlusSecurityGroups = [zillaPlusSG.securityGroupId];
    }

    const zillaPlusCapacity = this.node.tryGetContext('zillaPlusCapacity') ?? 2;

    const publicPort = this.node.tryGetContext('publicPort') ?? 9094;


  }
}
