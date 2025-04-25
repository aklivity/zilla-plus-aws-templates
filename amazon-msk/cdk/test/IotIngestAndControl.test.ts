import * as cdk from 'aws-cdk-lib';
import { IotIngestAndControlStack } from '../lib/IotIngestAndControlStack';
import { Template } from 'aws-cdk-lib/assertions';

test('IOT Ingest and Control Stack created', () => {

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
        "IotIngestAndControl":
        {
            "vpcId": "vpc-12345",
            "msk":
            {
                "servers": "b-1.mymskcluter.****.us-east-1.amazonaws.com:9096",
                "credentials": "AmazonMSK_Alice"
            },
            "public":
            {
              "servers": "mqtt.test.example.com:8883",
              "certificate": "arn:aws:secretsmanager:us-east-1:445711703002:secret:wildcard.example.aklivity.io-9-u4J0YL"
            },
            "ami": "ami-1234"
          }
        }
      }
    );
    const stack = new IotIngestAndControlStack(app, 'IotIngestAndControl', {
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
        Port: 8883,
        Protocol: `TCP`,
        VpcId: `vpc-12345`
    });

    template.hasResourceProperties('AWS::ElasticLoadBalancingV2::Listener', {
        LoadBalancerArn:
        {
            Ref: `ZillaPlusLoadBalancer4C8A1454`
        },
        Port: 8883,
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
            Enabled: false
          },
          ImageId: `ami-1234`
        },
    });
});
