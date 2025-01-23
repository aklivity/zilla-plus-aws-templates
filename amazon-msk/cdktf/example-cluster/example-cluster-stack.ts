import { Construct } from "constructs";
import { TerraformOutput, TerraformStack } from "cdktf";
import { SecurityGroup } from "@cdktf/provider-aws/lib/security-group";
import { Subnet } from "@cdktf/provider-aws/lib/subnet";
import { Vpc } from "@cdktf/provider-aws/lib/vpc";
import { MskCluster } from "@cdktf/provider-aws/lib/msk-cluster";
import { AwsProvider } from "@cdktf/provider-aws/lib/provider";
import { DataAwsRegion } from "@cdktf/provider-aws/lib/data-aws-region";
import { DataAwsAcmpcaCertificateAuthority } from "@cdktf/provider-aws/lib/data-aws-acmpca-certificate-authority";
import { SecretsmanagerSecret } from "@cdktf/provider-aws/lib/secretsmanager-secret";
import { SecretsmanagerSecretVersion } from "@cdktf/provider-aws/lib/secretsmanager-secret-version";
import { IamPolicy } from "@cdktf/provider-aws/lib/iam-policy";
import { IamPolicyAttachment } from "@cdktf/provider-aws/lib/iam-policy-attachment";
import { IamRole } from "@cdktf/provider-aws/lib/iam-role";
import { MskScramSecretAssociation } from "@cdktf/provider-aws/lib/msk-scram-secret-association";
import { KmsKey } from "@cdktf/provider-aws/lib/kms-key";
import { KmsAlias } from "@cdktf/provider-aws/lib/kms-alias";

export class ZillaPlusExampleMskCluster extends TerraformStack {
  constructor(scope: Construct, id: string) {
    super(scope, id);

    const awsProvider = new AwsProvider(this, "AWS", {});
    
    const zillaPlusContext = this.node.tryGetContext('zilla-plus');
    const mskCertificateAuthority = zillaPlusContext?.mskCertificateAuthorityArn;

    if (mskCertificateAuthority) {
      new DataAwsAcmpcaCertificateAuthority(this, "MSKCertificateAuthority", {
        arn: mskCertificateAuthority,
      });
    }

    const vpc = new Vpc(this, "MskVpc", {
      cidrBlock: "10.0.0.0/16",
      enableDnsHostnames: true,
      enableDnsSupport: true,
      tags: {
        Name: "msk-vpc",
      },
    });

    const region = new DataAwsRegion(this, "CurrentRegion", {
      provider: awsProvider,
    });

    const privateSubnet1 = new Subnet(this, "PrivateSubnet1", {
      vpcId: vpc.id,
      cidrBlock: "10.0.128.0/20",
      availabilityZone: `${region.name}a`,
      mapPublicIpOnLaunch: false,
      tags: {
        Name: "msk-private-subnet-1",
      },
    });

    const privateSubnet2 = new Subnet(this, "PrivateSubnet2", {
      vpcId: vpc.id,
      cidrBlock: "10.0.144.0/20",
      availabilityZone: `${region.name}b`,
      mapPublicIpOnLaunch: false,
      tags: {
        Name: "msk-private-subnet-2",
      },
    });

    const securityGroup = new SecurityGroup(this, "MskSecurityGroup", {
      vpcId: vpc.id,
      description: "Security group for MSK cluster",
      ingress: [
        {
          fromPort: 9092,
          toPort: 9096,
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
        Name: "msk-security-group",
      },
    });

    const kmsKey = new KmsKey(this, "MskKmsKey", {
      policy: JSON.stringify({
        Version: "2012-10-17",
        Id: "key-consolepolicy-3",
        Statement: [
          {
            Sid: "Enable IAM User Permissions",
            Effect: "Allow",
            Principal: {
              AWS: "*",
            },
            Action: "kms:*",
            Resource: "*",
          },
        ],
      }),
      description: "KMS key for MSK",
      keyUsage: "ENCRYPT_DECRYPT",
      customerMasterKeySpec: "SYMMETRIC_DEFAULT",
      isEnabled: true,
    });

    new KmsAlias(this, "MskKmsKeyAlias", {
      name: "alias/AmazonMSK_key",
      targetKeyId: kmsKey.keyId,
    });

    const saslScramSecret = new SecretsmanagerSecret(this, "SaslScramSecret", {
      name: "AmazonMSK_alice",
      kmsKeyId: kmsKey.keyId,
    });

    new SecretsmanagerSecretVersion(this, "SaslScramSecretVersion", {
      secretId: saslScramSecret.id,
      secretString: JSON.stringify({
        username: "alice",
        password: "alice-secret",
      }),
    });

    const mskIamRole = new IamRole(this, "MskIamRole", {
      assumeRolePolicy: JSON.stringify({
        Version: "2012-10-17",
        Statement: [
          {
            Effect: "Allow",
            Principal: {
              Service: "kafka.amazonaws.com",
            },
            Action: "sts:AssumeRole",
          },
        ],
      }),
    });

    const mskSecretsManagerPolicy = new IamPolicy(
      this,
      "MskSecretsManagerPolicy",
      {
        policy: JSON.stringify({
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Action: [
                "secretsmanager:GetSecretValue",
                "secretsmanager:DescribeSecret",
              ],
              Resource: saslScramSecret.arn,
            },
          ],
        }),
      }
    );

    new IamPolicyAttachment(this, "MskSecretsManagerPolicyAttachment", {
      name: "msk-secrets-manager-policy-attachment",
      roles: [mskIamRole.name],
      policyArn: mskSecretsManagerPolicy.arn,
    });

    const mskCluster = new MskCluster(this, "MskCluster", {
      clusterName: "my-msk-cluster",
      kafkaVersion: "3.5.1",
      numberOfBrokerNodes: 2,
      brokerNodeGroupInfo: {
        instanceType: "kafka.t3.small",
        clientSubnets: [privateSubnet1.id, privateSubnet2.id],
        securityGroups: [securityGroup.id],
      },
      encryptionInfo: {
        encryptionInTransit: {
          clientBroker: "TLS_PLAINTEXT",
          inCluster: true,
        },
      },
      clientAuthentication: {
        unauthenticated: true,
        sasl: {
          scram: true,
        },
      },
    });

    new MskScramSecretAssociation(this, "MskSecretsScramSecretAssociation", {
      clusterArn: mskCluster.arn,
      secretArnList: [saslScramSecret.arn],
    });

    if (mskCertificateAuthority) {
      mskCluster.clientAuthentication.putTls({
        certificateAuthorityArns: [mskCertificateAuthority],
      });
    }

    new TerraformOutput(this, "vpcId", {
      value: vpc.id,
    });

    new TerraformOutput(this, "privateSubnetIds", {
      value: [privateSubnet1.id, privateSubnet2.id],
    });

    new TerraformOutput(this, "mskClusterName", {
      value: mskCluster.clusterName,
    });
  }
}
