import * as cdk from 'aws-cdk-lib';
// import { Template } from 'aws-cdk-lib/assertions';
import * as ExampleCluster from '../lib/example-cluster-stack';
import { Template } from 'aws-cdk-lib/assertions';

// example test. To run these tests, uncomment this file along with the
// example resource in lib/example-cluster-stack.ts
test('Example cluster created', () => {
   const app = new cdk.App();

   const stack = new ExampleCluster.ZillaPlusExampleMskCluster(app, 'MyTestStack',
   {
    enableMtls: false,
    mskCertificateAuthorityArn: undefined,
  });

  const template = Template.fromStack(stack);

  template.hasResourceProperties('AWS::EC2::VPC', {
    CidrBlock: "10.0.0.0/16"
  });

  template.hasResourceProperties('AWS::EC2::Subnet', {
    CidrBlock: "10.0.0.0/24",
    MapPublicIpOnLaunch: false,
    VpcId:
    {
        Ref: "MskVpcA76CAC9E"
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
                ToPort: 9096,
            }
        ],
    });

    template.hasResourceProperties('AWS::MSK::Cluster', {
        BrokerNodeGroupInfo:
        {
            ClientSubnets:
            [
                {
                    Ref: "MskVpcPrivateSubnetSubnet1Subnet57B34710"
                },
                {
                    Ref: "MskVpcPrivateSubnetSubnet2Subnet197639D6"
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
