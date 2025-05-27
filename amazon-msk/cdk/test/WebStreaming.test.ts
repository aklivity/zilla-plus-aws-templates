import * as cdk from 'aws-cdk-lib';
import { WebStreamingStack } from '../lib/WebStreamingStack';
import { Template } from 'aws-cdk-lib/assertions';

test('Web Streaming Stack created', () => {

  const app = new cdk.App( {
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
      "WebStreaming":
      {
        "vpcId": "vpc-12345",
        "msk":
        {
          "servers": "b-1.mymskcluter.****.us-east-1.amazonaws.com:9096",
          "credentials": "AmazonMSK_Alice"
        },
        "public":
        {
          "servers": "web.test.example.com:7143",
          "certificate": "arn:aws:acm:us-east-1:****:certificate//*********"
        },
        "mappings": 
        [
          {"topic": "pets"}
        ],
        "ami": "ami-1234"
      }
    }
  });

  const stack = new WebStreamingStack(app, 'WebStreaming', {
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
      Port: 7143,
      Protocol: `TCP`,
      VpcId: `vpc-12345`
  });

  template.hasResourceProperties('AWS::ElasticLoadBalancingV2::Listener', {
      LoadBalancerArn:
      {
          Ref: `ZillaPlusLoadBalancer4C8A1454`
      },
      Port: 7143,
      Protocol: `TCP`,
  });
  

  template.hasResourceProperties('AWS::ElasticLoadBalancingV2::LoadBalancer', {
      IpAddressType: `ipv4`,
      Scheme: `internet-facing`,
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
