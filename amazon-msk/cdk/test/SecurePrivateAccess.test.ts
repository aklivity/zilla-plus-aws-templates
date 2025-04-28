import * as cdk from 'aws-cdk-lib';
import { SecurePrivateAccessStack } from '../lib/SecurePrivateAccessStack';
import { Template } from 'aws-cdk-lib/assertions';

test('SecurePrivateAccess stack created', () => {

  const app = new cdk.App({
    context: {
      "vpc-provider:account=12345678:filter.vpc-id=vpc-12345:region=us-east-1:returnAsymmetricSubnets=true": {
        "vpcId": "vpc-12345",
        "vpcCidrBlock": "10.0.0.0/16",
        "ownerAccountId": "12345678",
        "availabilityZones": [],
        "subnetGroups": [
          {
            "name": "PrivateSubnet",
            "type": "Isolated",
            "subnets": [
              {
                "subnetId": "subnet-1",
                "cidr": "10.0.0.0/24",
                "availabilityZone": "us-east-1a",
                "routeTableId": "rtb-1234"
              },
              {
                "subnetId": "subnet-2",
                "cidr": "10.0.1.0/24",
                "availabilityZone": "us-east-1b",
                "routeTableId": "rtb-5678"
              }
            ]
          }
        ]
      },
      "SecurePrivateAccess":
      {
        "vpcId": "vpc-12345",
        "subnetIds": ["subnet-1", "subnet-2"],
        "internal":
        {
          "servers": "boot-abcd.c1.kafka-serverless.us-east-1.amazonaws.com:9098"
        },
        "external":
        {
          "servers": "boot.example.aklivity.io:9098",
          "certificate": "arn:aws:acm:us-east-1:****:certificate//*********"
        },
        "ami": "ami-1234"
      }
    }
  }
  );

  const stack = new SecurePrivateAccessStack(app, 'SecurePrivateAccess', {
    env: {
      account: '12345678',
      region: 'us-east-1'
    }
  });

  const template = Template.fromStack(stack);

  template.hasResourceProperties('AWS::AutoScaling::AutoScalingGroup', {
    MaxSize: "5",
    MinSize: "2",
    TargetGroupARNs: [
      {
        "Ref": "ZillaPlusTargetGroup3E04D345"
      }
    ],
    VPCZoneIdentifier: [
      "subnet-1",
      "subnet-2"
    ]
  });

  template.hasResourceProperties('AWS::ElasticLoadBalancingV2::TargetGroup', {
    Port: 9098,
    Protocol: `TCP`,
    VpcId: `vpc-12345`
  });

  template.hasResourceProperties('AWS::ElasticLoadBalancingV2::Listener', {
    LoadBalancerArn:
    {
      Ref: `ZillaPlusLoadBalancer4C8A1454`
    },
    Port: 9098,
    Protocol: `TCP`,
  });

  template.hasResourceProperties('AWS::ElasticLoadBalancingV2::LoadBalancer', {
    IpAddressType: `ipv4`,
    Scheme: `internal`,
    Subnets: [
      "subnet-1",
      "subnet-2"
    ],
    Type: `network`
  });

  template.hasResourceProperties('AWS::EC2::LaunchTemplate', {
    LaunchTemplateData:
    {
      EnclaveOptions:
      {
        Enabled: true
      },
      ImageId: `ami-1234`
    },
  });
});
