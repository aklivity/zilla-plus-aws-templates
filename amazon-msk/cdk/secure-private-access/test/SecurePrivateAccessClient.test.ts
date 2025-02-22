import * as cdk from 'aws-cdk-lib';
import { SecurePrivateAccessClientStack } from '../lib/SecurePrivateAccessClientStack';
import { Template } from 'aws-cdk-lib/assertions';

test('SecurePrivateAccessStackClient stack created', () => {

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
      "SecurePrivateAccessClient": {
        "vpcId": "vpc-12345",
        "subnetIds": [
          "subnet-1"
        ],
        "wildcardDNS": "*.example.aklivity.io",
        "port": 9098
      }
    }
  });

  const stack = new SecurePrivateAccessClientStack(app, 'SecurePrivateAccessClient', {
    env: {
      account: '12345678',
      region: 'us-east-1'
    }
  });

  const template = Template.fromStack(stack);

  template.hasResourceProperties('AWS::Route53::HostedZone', {
    "Name": "example.aklivity.io.",
    "VPCs": [
      {
        "VPCId": "vpc-12345",
        "VPCRegion": "us-east-1"
      }
    ]
  });
});
