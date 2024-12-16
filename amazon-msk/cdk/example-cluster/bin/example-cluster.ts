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
      enableKeyRotation: true,
      description: 'KMS key for MSK cluster and Secrets',
    });

    const saslScramSecret = new secretsmanager.Secret(this, 'SaslScramSecret', {
      secretName: 'AmazonMSK_alice',
      encryptionKey: kmsKey,
      generateSecretString: {
        secretStringTemplate: JSON.stringify({ username: 'alice' }),
        generateStringKey: 'password',
      },
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

    new cdk.CfnOutput(this, 'MskClusterArn', {
      value: mskCluster.ref,
    });
  }
}

const app = new cdk.App();
new ZillaPlusExampleMskCluster(app, 'ZillaPlusExampleMskCluster', {
  enableMtls: process.env.MTLS_ENABLED === 'true',
  mskCertificateAuthorityArn: process.env.MTLS_ENABLED === 'true' ? process.env.MSK_CERTIFICATE_AUTHORITY_ARN : undefined,
});
