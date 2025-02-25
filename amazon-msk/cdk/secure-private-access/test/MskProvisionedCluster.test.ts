import * as cdk from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { MskProvisionedClusterStack } from '../lib/MskProvisionedClusterStack';

test('MskProvisionedCluster stack created', () => {
   const app = new cdk.App({
    context: {
      "MskProvisionedCluster": {
        "vpc": {
          "cidr": "10.4.0.0/16"
        },
        "subnets": {
          "cidrMask": 24
        },
        "authentication": {
          "unauthenticated": true,
          "sasl": {
            "iam": true,
            "scram": "bob"
          }
        }
      }
    }
  }
  );

  const stack = new MskProvisionedClusterStack(app, 'MskProvisionedCluster', {
    env: {
      account: '12345678',
      region: 'us-east-1'
    }
  });

  const template = Template.fromStack(stack);

  template.hasResourceProperties('AWS::EC2::VPC', {
    CidrBlock: "10.4.0.0/16"
  });

  template.hasResourceProperties('AWS::EC2::Subnet', {
    CidrBlock: "10.4.0.0/24",
    MapPublicIpOnLaunch: false,
    VpcId:
    {
        Ref: "ZillaPlusMskVpcCA7B140D"
    }
  });

  template.hasResourceProperties('AWS::IAM::Role', {
    AssumeRolePolicyDocument:
    {
        Version: "2012-10-17",
        Statement:
        [
            {      
                Action: "sts:AssumeRole",
                Effect: "Allow",
                Principal:
                {
                    Service: "kafka.amazonaws.com"
                }
            }
        ]
    }
  });

  template.hasResourceProperties('AWS::EC2::SecurityGroup', {
        SecurityGroupEgress:
        [
            {      
                CidrIp: "0.0.0.0/0"
            }
        ],
        SecurityGroupIngress:
        [
            {      
                CidrIp: "0.0.0.0/0",
                FromPort: 9092,
                IpProtocol: "tcp",
                ToPort: 9098,
            }
        ],
    });

    template.hasResourceProperties('AWS::MSK::Cluster', {
        BrokerNodeGroupInfo:
        {
            ClientSubnets:
            [
                {
                    Ref: "ZillaPlusMskVpcZillaPlusMskPrivateSubnet1Subnet0D870D15"
                },
                {
                    Ref: "ZillaPlusMskVpcZillaPlusMskPrivateSubnet2Subnet06666410"
                }
            ],
            InstanceType: "kafka.t3.small"
        },
        ClientAuthentication:
        {
            Sasl:
            {     
                Scram:
                {
                    Enabled: true
                }
            },
            Unauthenticated:
            {
                Enabled: true
            }
        },
        NumberOfBrokerNodes: 2
    });
});
