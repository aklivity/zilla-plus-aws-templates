import * as cdk from 'aws-cdk-lib';
import { SecurePublicAccessStack } from '../lib/SecurePublicAccessStack';
import { Template } from 'aws-cdk-lib/assertions';

test('Secure Public Access stack created', () => {

  const app = new cdk.App({
    context: {
      "vpc-provider:account=12345678:filter.vpc-id=vpc-12345:region=us-east-1:returnAsymmetricSubnets=true": {
        "vpcId": "vpc-12345",
        "vpcCidrBlock": "10.0.0.0/16",
        "ownerAccountId": "12345678",
        "availabilityZones": [],
        "subnetGroups": [
          {
            "name": "PublicSubnet",
            "type": "Public",
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
      "SecurePublicAccess": {
        "vpcId": "vpc-12345",
        "subnetIds": ["subnet-1", "subnet-2"],
        "internal": {
          "servers": "b-1.mymskcluster.****.us-east-1.amazonaws.com:9094"
        },
        "external": {
          "servers": "*.example.aklivity.io:9094",
          "certificate": "arn:aws:acm:us-east-1:****:certificate//*********"
        },
        "ami": "ami-1234"
      },
    }
  });

  const stack = new SecurePublicAccessStack(app, 'SecurePublicAccess', {
    env: {
      account: '12345678',
      region: 'us-east-1'
    },
    freeTrial: false
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
    Port: 9094,
    Protocol: "TCP",
    VpcId: "vpc-12345"
  });

  template.hasResourceProperties('AWS::ElasticLoadBalancingV2::Listener', {
    LoadBalancerArn:
    {
      Ref: "ZillaPlusLoadBalancer4C8A1454"
    },
    Port: 9094,
    Protocol: "TCP",
  });

  template.hasResourceProperties('AWS::ElasticLoadBalancingV2::LoadBalancer', {
    IpAddressType: "ipv4",
    Scheme: "internet-facing",
    Subnets: [
      "subnet-1",
      "subnet-2"
    ],
    Type: "network"
  });

  template.hasResourceProperties('AWS::EC2::LaunchTemplate', {
    LaunchTemplateData:
    {
      EnclaveOptions:
      {
        Enabled: true
      },
      ImageId: "ami-1234"
    },
  });
});
