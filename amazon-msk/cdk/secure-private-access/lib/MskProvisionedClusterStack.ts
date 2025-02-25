import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as msk from 'aws-cdk-lib/aws-msk';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

interface MskProvisionedClusterVpcContext {
  cidr: string
}

interface MskProvisionedClusterSubnetsContext {
  cidrMask: number
}

interface MskProvisionedClusterSaslProps {
  iam?: boolean,
  scram?: string
}

interface MskProvisionedClusterAuthenticationContext {
  unauthenticated?: boolean,
  sasl?: MskProvisionedClusterSaslProps,
  mtls?: Array<string>,
}

interface MskProvisionedClusterContext {
  vpc?: MskProvisionedClusterVpcContext,
  subnets?: MskProvisionedClusterSubnetsContext,
  authentication: MskProvisionedClusterAuthenticationContext;
}

export class MskProvisionedClusterStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // lookup context
    const context : MskProvisionedClusterContext = this.node.getContext(id);

    // default context values
    context.vpc ??= { cidr: '10.0.0.0/16' };
    context.subnets ??= { cidrMask: 24 };
    
    const vpc = new ec2.Vpc(this, 'ZillaPlus-MskVpc', {
      ipAddresses: ec2.IpAddresses.cidr(context.vpc.cidr),
      maxAzs: 2,
      subnetConfiguration: [
        {
          cidrMask: context.subnets.cidrMask,
          name: 'ZillaPlus-MskPrivate',
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED
        },
      ],
    });

    const securityGroup = new ec2.SecurityGroup(this, 'ZillaPlus-MskSecurityGroup', {
      vpc,
      description: 'Security group for MSK cluster',
      allowAllOutbound: true,
    });

    securityGroup.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcpRange(9092, 9098),
      'Allow Kafka traffic');

    const mskCluster = new msk.CfnCluster(this, 'ZillaPlus-MskCluster', {
      clusterName: `zilla-plus-${id}`,
      kafkaVersion: '3.5.1',
      numberOfBrokerNodes: 2,
      brokerNodeGroupInfo: {
        instanceType: 'kafka.t3.small',
        clientSubnets: vpc.isolatedSubnets.map(subnet => subnet.subnetId),
        securityGroups: [securityGroup.securityGroupId],
      },
      encryptionInfo: {
        encryptionInTransit: {
          clientBroker: context.authentication.unauthenticated
            ? 'TLS_PLAINTEXT'
            : 'TLS',
          inCluster: true,
        },
      },
      clientAuthentication: {
        unauthenticated: 
        {
          enabled: Boolean(context.authentication.unauthenticated)
        },
        sasl: {
          iam: {
            enabled: Boolean(context.authentication.sasl?.iam)
          },
          scram: {
            enabled: Boolean(context.authentication.sasl?.scram)
          },
        },
        ...(context.authentication.mtls
          ? {
              tls: {
                enabled: Boolean(context.authentication.mtls),
                certificateAuthorityArnList: context.authentication.mtls
              }
            }
          : {})
      },
    });

    const mskIamRole = new iam.Role(this, 'ZillaPlus-MskIamRole', {
      assumedBy: new iam.ServicePrincipal('kafka.amazonaws.com'),
    });

    const username = context.authentication?.sasl?.scram;

    if (username) {
      const kmsKey = new kms.Key(this, 'ZillaPlus-MskKmsKey', {
        description: 'KMS key for MSK',
        enableKeyRotation: false,
        enabled: true,
      });
  
      kmsKey.addToResourcePolicy(
        new iam.PolicyStatement({
          sid: 'Enable IAM User Permissions',
          effect: cdk.aws_iam.Effect.ALLOW,
          principals: [new cdk.aws_iam.ArnPrincipal('*')],
          actions: ['kms:*'],
          resources: ['*'],
        })
      );

      const secret = new secretsmanager.Secret(this, 'ZillaPlus-MskSaslScramSecret', {
        secretName: `AmazonMSK_${username}`,
        encryptionKey: kmsKey,
        secretStringValue: cdk.SecretValue.unsafePlainText(
          JSON.stringify({
            username: username,
            password: `${username}-secret`
          })
        ),
      });

      secret.grantRead(mskIamRole);

      new msk.CfnBatchScramSecret(this, 'ZillaPlus-MskBatchScramSecret', {
        clusterArn: mskCluster.attrArn,
        secretArnList: [secret.secretArn],
      });
    }

    new cdk.CfnOutput(this, 'ClusterArn', {
      value: mskCluster.ref,
    });

    new cdk.CfnOutput(this, 'VpcId', {
      value: vpc.vpcId,
    });

    new cdk.CfnOutput(this, 'SubnetIds', {
      value: JSON.stringify(vpc.isolatedSubnets.map(subnet => subnet.subnetId)),
    });
  }
}
