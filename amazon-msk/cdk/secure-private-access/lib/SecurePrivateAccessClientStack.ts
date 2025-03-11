import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as route53 from 'aws-cdk-lib/aws-route53';
import { Construct, Node } from 'constructs';
import { validateRequiredKeys } from './validateRequiredKeys';
import { InterfaceVpcEndpointTarget } from 'aws-cdk-lib/aws-route53-targets';

export class SecurePrivateAccessClientStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // lookup context
    const context = this.node.getContext(id);

    // validate context
    validateRequiredKeys(context, [ 'vpcId', 'server' ]);

    // default context values
    context.vpceServiceName ??= cdk.Fn.importValue("SecurePrivateAccess-VpcEndpointServiceName");

    const [server, port] = context.server.split(',')[0].split(':');

    const vpc = ec2.Vpc.fromLookup(this, 'ClientVpc', { vpcId: context.vpcId });
    const subnets = vpc.selectSubnets({
      subnetFilters: [
        context.subnetIds
          ? ec2.SubnetFilter.byIds(context.subnetIds)
          : ec2.SubnetFilter.onePerAz()
      ]
    });

    const securityGroup = new ec2.SecurityGroup(this, 'Client-VpcEndpoint-SecurityGroup', {
      description: `Client VPC Endpoint Security Group`,
      vpc: vpc,
    });

    securityGroup.addIngressRule(
      ec2.Peer.ipv4(vpc.vpcCidrBlock),
      ec2.Port.tcp(Number(port)),
      'Allow inbound traffic on Kafka IAM port');

    const vpcEndpoint = new ec2.InterfaceVpcEndpoint(this, 'Client-VpcEndpoint', {
      vpc: vpc,
      subnets: subnets,
      securityGroups: [securityGroup],
      service : new ec2.InterfaceVpcEndpointService(context.vpceServiceName),
    });
    
    const hostedZone = new route53.PrivateHostedZone(this, 'Client-HostedZone', {
      vpc: vpc,
      zoneName: server.replace(/[^.]+./, '')
    });

    new route53.RecordSet(this, 'Client-HostedZoneRecords', {
      zone: hostedZone,
      recordType: route53.RecordType.A,
      recordName: '*',
      target: route53.RecordTarget.fromAlias(new InterfaceVpcEndpointTarget(vpcEndpoint))
    });

    cdk.Tags.of(securityGroup).add('Name', `ZillaPlus-${id}`);
    cdk.Tags.of(hostedZone).add('Name', `ZillaPlus-${id}`);
    cdk.Tags.of(vpcEndpoint).add('Name', `ZillaPlus-${id}`);

    new cdk.CfnOutput(this, 'VpcEndpointId', { 
      description: "ID of the VPC Endpoint",
      value: vpcEndpoint.vpcEndpointId
    });
  }
}
