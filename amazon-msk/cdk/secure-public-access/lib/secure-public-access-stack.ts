import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import { UserVariables } from './variables';
import  * as subnetCalculator from './subnet-calculator';


export class ZillaPlusSecurePublicAccessStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const userVariables = new UserVariables(this, "main");

    const vpcId = this.node.tryGetContext('vpcId');

    const vpc = ec2.Vpc.fromLookup(this, 'Vpc', { vpcId: vpcId });

    const subnets = vpc.publicSubnets;
    // Create Internet Gateway
    const internetGateway = new ec2.CfnInternetGateway(this, `InternetGateway-${id}`, {
      tags: [{ key: 'Name', value: 'my-igw' }],
    });

    // Attach Internet Gateway to VPC
    new ec2.CfnVPCGatewayAttachment(this, `VpcGatewayAttachment-${id}`, {
      vpcId: vpcId,
      internetGatewayId: internetGateway.ref,
    });

    // Create Public Route Table
    const publicRouteTable = new ec2.CfnRouteTable(this, `PublicRouteTable-${id}`, {
      vpcId: vpcId,
      tags: [{ key: 'Name', value: 'public-route-table' }],
    });

    // Create Route in the Public Route Table
    new ec2.CfnRoute(this, `PublicRoute-${id}`, {
      routeTableId: publicRouteTable.ref,
      destinationCidrBlock: '0.0.0.0/0',
      gatewayId: internetGateway.ref,
    });

    const existingSubnets = vpc.isolatedSubnets.concat(vpc.publicSubnets, vpc.privateSubnets);
    const existingCidrBlocks = existingSubnets.map((subnet) => subnet.ipv4CidrBlock);

    const availableCidrBlocks = subnetCalculator.findAvailableCidrBlocks(
      vpc.vpcCidrBlock,
      existingCidrBlocks,
      2);

    console.log("Hello: " + availableCidrBlocks);

    // Function to find an available CIDR block
    const findAvailableCidrBlock = (baseCidr: string, existing: string[], count: number): string[] => {
      const generatedCidrBlocks = cdk.Fn.cidr(baseCidr, count * 2, '24');

      const filteredCidrBlocks: string[] = [];
      for (let i = 0; i < cdk.Fn.len(generatedCidrBlocks); i++) {
        const cidrBlock = cdk.Fn.select(i, generatedCidrBlocks);
        const isExcluded = existingCidrBlocks.includes(cidrBlock);
  
        // Add only if not excluded
        if (!isExcluded) {
          filteredCidrBlocks.push(cidrBlock);
        }
      }
      return filteredCidrBlocks;
    };

    const availabilityZones = cdk.Fn.getAzs();
    const subnetIds: string[] = [];

    for (let i = 0; i < 2; i++) {
      const az = cdk.Fn.select(i, availabilityZones);
      const cidrBlock = cdk.Fn.select(i, availableCidrBlocks);

      // Create the subnet
      const subnet = new ec2.CfnSubnet(this, `Subnet${i + 1}`, {
        vpcId: vpcId,
        cidrBlock: cidrBlock,
        availabilityZone: az,
        mapPublicIpOnLaunch: true,
        tags: [
          {
            key: 'Name',
            value: `public-subnet-${i + 1}-${id}`,
          },
        ],
      });

      subnetIds.push(subnet.ref);

      // Associate the subnet with the provided route table
      new ec2.CfnSubnetRouteTableAssociation(this, `Subnet${i + 1}RouteTableAssociation`, {
        subnetId: subnet.ref,
        routeTableId: publicRouteTable.ref,
      });
    }

    // for (let i = 1; i <= 2; i++) {
    //   const az = cdk.Fn.select(i - 1, availabilityZones);
    //   const subnetIndex = i;
    //   const cidrBlock = cdk.Fn.cidr(vpc.vpcCidrBlock, subnetsMax.toString(), subnetIndex.toString());

    //   // Create Public Subnets
    //   const publicSubnet = new ec2.CfnSubnet(this, `PublicSubnet${i}-${id}`, {
    //     vpcId: props.vpcId,
    //     cidrBlock: cidrBlock,
    //     availabilityZone: az,
    //     mapPublicIpOnLaunch: true,
    //     tags: [{ key: 'Name', value: `public-subnet-${subnetIndex}-${id}` }],
    //   });

    //   subnetIds.push(publicSubnet.ref);

    //   // Associate Subnet with Public Route Table
    //   new ec2.CfnSubnetRouteTableAssociation(this, `PublicSubnet${i}RouteTableAssociation-${id}`, {
    //     subnetId: publicSubnet.ref,
    //     routeTableId: publicRouteTable.ref,
    //   });
    // }
    
    new cdk.CfnOutput(this, 'subnets', { value: subnetIds.join(',') });

  }

    private calculateSubnetSize(cidrBlock: string): number {
      const subnetPrefixSize = parseInt(cidrBlock.split('/')[1], 10);
      const totalIps = Math.pow(2, 32 - subnetPrefixSize);
      return totalIps;
    }
}
