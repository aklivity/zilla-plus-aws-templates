import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as msk from 'aws-cdk-lib/aws-msk';
import { Construct } from 'constructs';

interface MskServerlessClusterVpcContext {
  cidr: string
}

interface MskServerlessClusterSubnetsContext {
  public: MskServerlessClusterSubnetContext,
  private: MskServerlessClusterSubnetContext
}

interface MskServerlessClusterSubnetContext {
  cidrMask: number
}

interface MskServerlessClusterContext {
  vpc?: MskServerlessClusterVpcContext,
  subnets?: MskServerlessClusterSubnetsContext,
}

export class MskServerlessClusterStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // lookup context
    const context : MskServerlessClusterContext = this.node.tryGetContext(id) || {};

    // default context values
    context.vpc ??= { cidr: '10.0.0.0/16' };
    context.subnets ??= { private: { cidrMask: 24 }, public: { cidrMask: 24 } };
    
    const vpc = new ec2.Vpc(this, 'ZillaPlus-MskVpc', {
      vpcName: `ZillaPlus-${id}`,
      ipAddresses: ec2.IpAddresses.cidr(context.vpc.cidr),
      maxAzs: 2,
      subnetConfiguration: [
        {
          cidrMask: context.subnets?.private.cidrMask,
          name: 'ZillaPlus-MskPrivate',
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED
        }
      ],
    });

    const subnets = vpc.selectSubnets({
      subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
      subnetFilters: [
        ec2.SubnetFilter.onePerAz()
      ]
    });

    if (subnets.isPendingLookup) {
      return;
    }

    const securityGroup = new ec2.SecurityGroup(this, 'ZillaPlus-MskSecurityGroup', {
      vpc,
      description: 'Security group for MSK cluster',
      allowAllOutbound: true,
    });

    securityGroup.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcpRange(9092, 9098),
      'Allow Kafka traffic');

    const mskCluster = new msk.CfnServerlessCluster(this, 'ZillaPlus-MskCluster', {
      clusterName: `ZillaPlus-${id}`,
      clientAuthentication: {
        "sasl": {
          "iam": {
            "enabled": true
          }
        }
      },
      vpcConfigs: [
        {
          subnetIds: vpc.isolatedSubnets.map(subnet => subnet.subnetId),
          securityGroups: [securityGroup.securityGroupId],
        }
      ],
    });

    const resources = {
      cluster: `arn:aws:kafka:${this.region}:${this.account}:cluster/${mskCluster.clusterName}/*`,
      topic: `arn:aws:kafka:${this.region}:${this.account}:topic/${mskCluster.clusterName}/*`,
      group: `arn:aws:kafka:${this.region}:${this.account}:group/${mskCluster.clusterName}/*`
    };

    const role = new iam.Role(this, `ZillaPlus-MskClusterRole`, {
      roleName: `ZillaPlus-${id}`,
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      inlinePolicies: {
        MskServerlessClusterPolicy: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: [
                'kafka-cluster:Connect',
                'kafka-cluster:AlterCluster',
                'kafka-cluster:DescribeCluster'
              ],
              resources: [
                resources.cluster
              ],
            }),
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: [
                  "kafka-cluster:*Topic*",
                  "kafka-cluster:WriteData",
                  "kafka-cluster:ReadData"
              ],
              resources: [
                resources.topic
              ]
            }),
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: [
                  "kafka-cluster:AlterGroup",
                  "kafka-cluster:DescribeGroup"
              ],
              resources: [
                resources.group
              ]
            })
          ],
        })
      }
    });

    new iam.InstanceProfile(this, `ZillaPlus-MskClusterProfile`, {
      role: role
    });

    const endpoints: Record<string, ec2.InterfaceVpcEndpointAwsService> = {
      "ssm": ec2.InterfaceVpcEndpointAwsService.SSM,
      "cloudformation": ec2.InterfaceVpcEndpointAwsService.CLOUDFORMATION,
      "ssm_messages": ec2.InterfaceVpcEndpointAwsService.SSM_MESSAGES,
      "ec2_messages": ec2.InterfaceVpcEndpointAwsService.EC2_MESSAGES,
      "secretsmanager": ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
      "monitoring": ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_MONITORING,
      "cloudwatch": ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
      "acm-pca": ec2.InterfaceVpcEndpointAwsService.PRIVATE_CERTIFICATE_AUTHORITY,
      "kms": ec2.InterfaceVpcEndpointAwsService.KMS,
      "s3": ec2.InterfaceVpcEndpointAwsService.S3,
      "iam": ec2.InterfaceVpcEndpointAwsService.IAM
    };

    for (const serviceName in endpoints) {
      if (endpoints.hasOwnProperty(serviceName)) {
        if (serviceName == "s3") {
          vpc.addGatewayEndpoint("Endpoint-s3-gateway", {
            service: ec2.GatewayVpcEndpointAwsService.S3,
            subnets: [subnets],
          });
        }

        const service = endpoints[serviceName as keyof typeof endpoints];
        vpc.addInterfaceEndpoint(`Endpoint-${serviceName}`, {
          service: service,
          subnets: subnets,
          securityGroups: [securityGroup]
        });
      }
    }

    new cdk.CfnOutput(this, 'ClusterArn', {
      value: mskCluster.ref,
    });

    new cdk.CfnOutput(this, 'RoleArn', {
      value: role.roleArn,
    });

    new cdk.CfnOutput(this, 'VpcId', {
      value: vpc.vpcId,
      exportName: `${id}-VpcId`
    });

    new cdk.CfnOutput(this, 'SubnetIds', {
      value: JSON.stringify(vpc.isolatedSubnets.map(subnet => subnet.subnetId)),
    });
  }
}
