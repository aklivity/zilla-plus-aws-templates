import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as msk from 'aws-cdk-lib/aws-msk';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as iam from 'aws-cdk-lib/aws-iam';

interface ZillaPlusExampleMskClusterProps extends cdk.StackProps {
  enableMtls?: boolean;
  mskCertificateAuthorityArn?: string;
}

export class ZillaPlusExampleMskCluster extends cdk.Stack {
  constructor(scope: Construct, id: string, props: ZillaPlusExampleMskClusterProps) {
    super(scope, id, props);

    const { enableMtls = false, mskCertificateAuthorityArn } = props;

    const vpc = new ec2.Vpc(this, 'MskVpc', {
      cidr: '10.0.0.0/16',
      maxAzs: 2,
      subnetConfiguration: [
        {
          cidrMask: 24,
          name: 'PrivateSubnet',
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED
        },
      ],
    });

    const securityGroup = new ec2.SecurityGroup(this, 'MskSecurityGroup', {
      vpc,
      description: 'Security group for MSK cluster',
      allowAllOutbound: true,
    });

    securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcpRange(9092, 9096), 'Allow Kafka traffic');

    const kmsKey = new kms.Key(this, 'MskKmsKey', {
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
    const saslScramSecret = new secretsmanager.Secret(this, 'SaslScramSecret', {
      secretName: 'AmazonMSK_alice', // The name of the secret
      encryptionKey: kmsKey, // Use the KMS key for encryption
      secretStringValue: cdk.SecretValue.unsafePlainText(
        JSON.stringify({
          username: 'alice',
          password: 'alice-secret', // Replace with the actual secret value
        })
      ),
    });

    const mskIamRole = new iam.Role(this, 'MskIamRole', {
      assumedBy: new iam.ServicePrincipal('kafka.amazonaws.com'),
    });

    saslScramSecret.grantRead(mskIamRole);

    const mskCluster = new msk.CfnCluster(this, 'MskCluster', {
      clusterName: 'my-msk-cluster',
      kafkaVersion: '3.5.1',
      numberOfBrokerNodes: 2,
      brokerNodeGroupInfo: {
        instanceType: 'kafka.t3.small',
        clientSubnets: vpc.isolatedSubnets.map(subnet => subnet.subnetId),
        securityGroups: [securityGroup.securityGroupId],
      },
      encryptionInfo: {
        encryptionInTransit: {
          clientBroker: 'TLS_PLAINTEXT',
          inCluster: true,
        },
      },
      clientAuthentication: {
        unauthenticated: 
        {
          enabled: true
        },
        sasl: {
          scram: {
            enabled: true
          },
        },
        ...(enableMtls && mskCertificateAuthorityArn
          ? {
              tls: {
                certificateAuthorityArnList: [mskCertificateAuthorityArn],
              },
            }
          : {}),
      },
    });

    new msk.CfnBatchScramSecret(this, 'MyCfnBatchScramSecret', {
      clusterArn: mskCluster.attrArn,
      secretArnList: [saslScramSecret.secretArn],
    });

    new cdk.CfnOutput(this, 'MskClusterArn', {
      value: mskCluster.ref,
    });
  }
}
