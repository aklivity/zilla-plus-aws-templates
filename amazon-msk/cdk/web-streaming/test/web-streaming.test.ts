import * as cdk from 'aws-cdk-lib';
import * as web from '../lib/web-streaming-stack';
import { Template } from 'aws-cdk-lib/assertions';

test('Secure Public Access Stack created', () => {

    const app = new cdk.App( {
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
                  "zilla-plus":
                  {
                      "vpcId": "vpc-12345",
                      "msk":
                      {
                        "servers": "b-1.mymskcluter.****.us-east-1.amazonaws.com:9096",
                        "credentials": "AmazonMSK_Alice"
                      },
                      "public":
                      {
                        "certificate": "arn:aws:acm:us-east-1:****:certificate//*********"
                      },
                      "mappings": 
                      [
                        {"topic": "pets"}
                      ]
                  }
            }
        }
    );
    const stack = new web.WebStreamingStack(app, 'MyTestStack', {
        env: {
            account: '12345678',
            region: 'us-east-1'
        }

    });

    const template = Template.fromStack(stack);

    console.log(template);

    template.hasResourceProperties('AWS::AutoScaling::AutoScalingGroup', {
        DesiredCapacity: "2",
        MaxSize: "5",
        MinSize: "1",
        TargetGroupARNs: [ 
            { 
                "Ref": "NLBTargetGroupMyTestStack" 
            }
        ],
        VPCZoneIdentifier: [
            {
                "Ref": "Subnet1"
            },
            {
                "Ref": "Subnet2"
            }
        ]
    });

    template.hasResourceProperties('AWS::ElasticLoadBalancingV2::TargetGroup', {
        Name: `nlb-tg-MyTestStack`,
        Port: 7143,
        Protocol: `TCP`,
        VpcId: `vpc-12345`
    });

    template.hasResourceProperties('AWS::ElasticLoadBalancingV2::Listener', {
        LoadBalancerArn:
        {
            Ref: `NetworkLoadBalancerMyTestStack`
        },
        Port: 7143,
        Protocol: `TCP`,
    });
    

    template.hasResourceProperties('AWS::ElasticLoadBalancingV2::LoadBalancer', {
        IpAddressType: `ipv4`,
        Name: `nlb-MyTestStack`,
        Scheme: `internet-facing`,
        Subnets: [
            {
                "Ref": "Subnet1"
            },
            {
                "Ref": "Subnet2"
            }
        ],
        Type: `network`
    });

    template.hasResourceProperties('AWS::EC2::LaunchTemplate', {
        LaunchTemplateData:
        {
            IamInstanceProfile:
            {
                Name:
                {
                    Ref: `ZillaPlusInstanceProfileMyTestStack`
                }
            },
            ImageId: `ami-1234`,
            NetworkInterfaces:
            [
                {
                    AssociatePublicIpAddress: true,
                    DeviceIndex: 0
                }
            ]
        },
    });
});
