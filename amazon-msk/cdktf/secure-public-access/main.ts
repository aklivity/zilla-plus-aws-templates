import { UserVariables } from "./variables";
import { Construct } from "constructs";
import {
  App,
  TerraformStack,
  TerraformOutput,
  TerraformVariable,
  Fn,
  Op,
} from "cdktf";
import instanceTypes from "./instance-types";
import { AwsProvider } from "@cdktf/provider-aws/lib/provider";
import { Lb } from "@cdktf/provider-aws/lib/lb";
import { LbListener } from "@cdktf/provider-aws/lib/lb-listener";
import { dataAwsAmi, launchTemplate } from "@cdktf/provider-aws";
import { autoscalingGroup } from "@cdktf/provider-aws";
import { LbTargetGroup } from "@cdktf/provider-aws/lib/lb-target-group";
import { DataAwsAcmpcaCertificateAuthority } from "@cdktf/provider-aws/lib/data-aws-acmpca-certificate-authority";
import { DataAwsSecretsmanagerSecretVersion } from "@cdktf/provider-aws/lib/data-aws-secretsmanager-secret-version";
import { CloudwatchLogGroup } from "@cdktf/provider-aws/lib/cloudwatch-log-group";
import { DataAwsMskCluster } from "@cdktf/provider-aws/lib/data-aws-msk-cluster";
import { InternetGateway } from "@cdktf/provider-aws/lib/internet-gateway";
import { Route } from "@cdktf/provider-aws/lib/route";
import { RouteTable } from "@cdktf/provider-aws/lib/route-table";
import { RouteTableAssociation } from "@cdktf/provider-aws/lib/route-table-association";
import { Subnet } from "@cdktf/provider-aws/lib/subnet";
import { IamRole } from "@cdktf/provider-aws/lib/iam-role";
import { IamRolePolicy } from "@cdktf/provider-aws/lib/iam-role-policy";
import { DataAwsMskBrokerNodes } from "@cdktf/provider-aws/lib/data-aws-msk-broker-nodes";
import { DataAwsSubnet } from "@cdktf/provider-aws/lib/data-aws-subnet";
import { DataAwsVpc } from "@cdktf/provider-aws/lib/data-aws-vpc";
import { DataAwsRegion } from "@cdktf/provider-aws/lib/data-aws-region";
import { SecurityGroup } from "@cdktf/provider-aws/lib/security-group";
import { DataAwsAvailabilityZones } from "@cdktf/provider-aws/lib/data-aws-availability-zones";
import { DataAwsSubnets } from "@cdktf/provider-aws/lib/data-aws-subnets";
import { IamInstanceProfile } from "@cdktf/provider-aws/lib/iam-instance-profile";

export class ZillaPlusSecurePublicAccessStack extends TerraformStack {
  constructor(scope: Construct, id: string) {
    super(scope, id);
    const userVariables = new UserVariables(this, "main");

    const awsProvider = new AwsProvider(this, "AWS", {});

    const region = new DataAwsRegion(this, "CurrentRegion", {
      provider: awsProvider,
    });

    let mskPort;
    let mskWildcardDNS;
    let mskCertificateAuthority;

    const mskClusterName = new TerraformVariable(this, "msk_cluster_name", {
      type: "string",
      description: "The name of the MSK cluster",
    });

    const mskCluster = new DataAwsMskCluster(this, "MSKCluster", {
      clusterName: mskClusterName.stringValue,
    });

    const mskClusterBrokerNodes = new DataAwsMskBrokerNodes(
      this,
      "MSKClusterBrokerNodes",
      {
        clusterArn: mskCluster.arn,
      }
    );

    const subnetId = mskClusterBrokerNodes.nodeInfoList.get(0).clientSubnet;

    const subnet = new DataAwsSubnet(this, "Subnet", {
      id: subnetId,
    });

    const vpc = new DataAwsVpc(this, "Vpc", {
      id: subnet.vpcId,
    });

    const subnets = new DataAwsSubnets(this, "PublicSubnets", {
      filter: [
        {
          name: "vpc-id",
          values: [vpc.id],
        },
      ],
    });

    const igw = new InternetGateway(this, "InternetGateway", {
      vpcId: vpc.id,
      tags: {
        Name: "my-igw",
      },
    });

    const publicRouteTable = new RouteTable(this, "PublicRouteTable", {
      vpcId: vpc.id,
      tags: {
        Name: "public-route-table",
      },
    });

    new Route(this, "PublicRoute", {
      routeTableId: publicRouteTable.id,
      destinationCidrBlock: "0.0.0.0/0",
      gatewayId: igw.id,
    });

    const availabilityZones = new DataAwsAvailabilityZones(this, "AZs", {});
    const subnetOffset = subnets.ids.length;
    const subnetMask = Fn.parseint(
      Fn.element(Fn.split("/", vpc.cidrBlock), 1),
      10
    );
    const availableIpv4 = subnet.availableIpAddressCount;
    // Math magic to find next power of 2 and based on the subnetAddressPower
    const subnetAddressPower = Fn.log(
      Fn.pow(2, Fn.ceil(Fn.log(availableIpv4, 2))),
      2
    );
    const subnetsMax = Op.sub(32, Op.add(subnetAddressPower, subnetMask));

    const subnetIds = [];
    for (let i = 1; i < 3; i++) {
      const az = Fn.element(availabilityZones.names, i);
      const subnetIndex = subnetOffset + i;
      const cidrBlock = Fn.cidrsubnet(
        vpc.cidrBlock,
        subnetsMax,
        subnetIndex + i
      );

      const subnet = new Subnet(this, `PublicSubnet${i}`, {
        vpcId: vpc.id,
        cidrBlock: cidrBlock,
        availabilityZone: az,
        mapPublicIpOnLaunch: true,
        tags: {
          Name: `public-subnet--${subnetIndex + 1}`,
        },
      });

      subnetIds.push(subnet.id);

      new RouteTableAssociation(this, `PublicSubnet${i}RouteTableAssociation`, {
        subnetId: subnet.id,
        routeTableId: publicRouteTable.id,
      });
    }

    let mskClientAuthentication;
    if (userVariables.mskClientAuthentication === "Unknown") {
      mskClientAuthentication = mskCluster.bootstrapBrokersTls
        ? "mTLS"
        : mskCluster.bootstrapBrokersSaslScram
        ? "SASL/SCRAM"
        : mskCluster.bootstrapBrokers
        ? "Unauthorized"
        : userVariables.mskClientAuthentication;
    }

    const bootstrapServers =
      mskClientAuthentication === "mTLS"
        ? mskCluster.bootstrapBrokersTls
        : mskClientAuthentication === "SASL/SCRAM"
        ? mskCluster.bootstrapBrokersSaslScram
        : mskCluster.bootstrapBrokers;

    const domainParts = Fn.split(
      ":",
      Fn.element(Fn.split(",", bootstrapServers), 0)
    );
    const serverAddress = Fn.element(domainParts, 0);
    mskPort = Fn.element(domainParts, 1);
    const addressParts = Fn.split(".", serverAddress);
    const mskBootstrapCommonPart = Fn.join(
      ".",
      Fn.slice(addressParts, 1, Fn.lengthOf(addressParts))
    );
    mskWildcardDNS = Fn.format("*.%s", [mskBootstrapCommonPart]);

    let tlsTrust = "";
    let tlsClientSigners = "";
    if (mskClientAuthentication === "mTLS") {
      // Seems like we can't get this from the MSK Cluster
      const mskCertificateAuthorityVar = new TerraformVariable(
        this,
        "msk_certificate_authority_arn",
        {
          type: "string",
          description:
            "ACM Private Certificate Authority ARN used to authorize clients connecting to the MSK cluster",
        }
      );
      // Validate that the PCA exists
      new DataAwsAcmpcaCertificateAuthority(this, "MSKCertificateAuthority", {
        arn: mskCertificateAuthorityVar.stringValue,
      });
      mskCertificateAuthority = mskCertificateAuthorityVar.stringValue;

      let publicCertificateAuthority = mskCertificateAuthority;
      if (userVariables.publicCertificateAuthority) {
        const publicCertificateAuthorityVar = new TerraformVariable(
          this,
          "public_certificate_authority_arn",
          {
            type: "string",
            description:
              "ACM Private Certificate Authority ARN used to authorize clients connecting to the Public Zilla Plus",
            default: mskCertificateAuthorityVar.stringValue,
          }
        );

        // Validate that the PCA exists
        new DataAwsAcmpcaCertificateAuthority(
          this,
          "publicCertificateAuthority",
          {
            arn: publicCertificateAuthorityVar.stringValue,
          }
        );
        publicCertificateAuthority = publicCertificateAuthorityVar.stringValue;
      }

      tlsTrust = `      trust:
        - ${publicCertificateAuthority}`;
      tlsClientSigners = `      signers:
- ${mskCertificateAuthority}`;
    }

    let zillaPlusRole;
    if (!userVariables.createZillaPlusRole) {
      const zillaPlusRoleVar = new TerraformVariable(
        this,
        "zilla_plus_role_name",
        {
          type: "string",
          description: "The role name assumed by Zilla Plus instances.",
        }
      );

      zillaPlusRole = zillaPlusRoleVar.stringValue;
    } else {
      const iamRole = new IamRole(this, "zilla_plus_role", {
        name: "zilla_plus_role",
        assumeRolePolicy: JSON.stringify({
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Principal: {
                Service: "ec2.amazonaws.com",
              },
              Action: "sts:AssumeRole",
            },
            {
              Effect: "Allow",
              Principal: {
                Service: "cloudformation.amazonaws.com",
              },
              Action: "sts:AssumeRole",
            },
          ],
        }),
        managedPolicyArns: [
          "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
          "arn:aws:iam::aws:policy/AWSCertificateManagerReadOnly",
          "arn:aws:iam::aws:policy/AWSGlueSchemaRegistryReadonlyAccess",
          "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess",
        ],
        inlinePolicy: [
          {
            name: "CCProxySecretsManagerRead",
            policy: JSON.stringify({
              Version: "2012-10-17",
              Statement: [
                {
                  Sid: "VisualEditor0",
                  Effect: "Allow",
                  Action: [
                    "acm-pca:GetCertificate",
                    "acm-pca:GetCertificateAuthorityCertificate",
                    "acm-pca:DescribeCertificateAuthority",
                    "tag:GetResources",
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:DescribeSecret",
                  ],
                  Resource: [
                    "arn:aws:secretsmanager:*:*:secret:wildcard.example.aklivity.io*",
                    "arn:aws:secretsmanager:*:*:secret:client-*",
                    "*",
                  ],
                },
              ],
            }),
          },
        ],
      });

      const iamInstanceProfile = new IamInstanceProfile(
        this,
        "zilla_plus_instance_profile",
        {
          name: "zilla_plus_role",
          role: iamRole.name,
        }
      );

      new IamRolePolicy(this, "ZillaPlusRolePolicy", {
        role: iamRole.name,
        policy: JSON.stringify({
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "VisualEditor0",
              Effect: "Allow",
              Action: [
                "secretsmanager:GetSecretValue",
                "secretsmanager:DescribeSecret",
              ],
              Resource: ["arn:aws:secretsmanager:*:*:secret:*"],
            },
          ],
        }),
      });

      zillaPlusRole = iamInstanceProfile.name;
    }

    let zillaPlusSecurityGroups;

    if (!userVariables.createZillaPlusSecurityGroup) {
      const zillaPlusSecurityGroupsVar = new TerraformVariable(
        this,
        "zilla_plus_security_groups",
        {
          type: "list(string)",
          description:
            "The security groups associated with Zilla Plus instances.",
        }
      );
      zillaPlusSecurityGroups = zillaPlusSecurityGroupsVar.listValue;
    } else {
      const zillaPlusSG = new SecurityGroup(this, "ZillaPlusSecurityGroup", {
        vpcId: vpc.id,
        description: "Security group for Zilla Plus",
        ingress: [
          {
            fromPort: 9092,
            toPort: 9096,
            protocol: "tcp",
            cidrBlocks: ["0.0.0.0/0"],
          },
        ],
        egress: [
          {
            fromPort: 0,
            toPort: 65535,
            protocol: "tcp",
            cidrBlocks: ["0.0.0.0/0"],
          },
        ],
        tags: {
          Name: "zilla-plus-security-group",
        },
      });
      zillaPlusSecurityGroups = [zillaPlusSG.id];
    }

    const zillaPlusCapacity = new TerraformVariable(
      this,
      "zilla_plus_capacity",
      {
        type: "number",
        default: 2,
        description: "The initial number of Zilla Plus instances",
      }
    );

    const publicPort = new TerraformVariable(this, "public_port", {
      type: "number",
      default: 9094,
      description: "The public port number to be used by Kafka clients",
    });

    const publicWildcardDNS = new TerraformVariable(
      this,
      "public_wildcard_dns",
      {
        type: "string",
        description:
          "The public wildcard DNS pattern for bootstrap servers to be used by Kafka clients",
      }
    );

    const publicTlsCertificateKey = new TerraformVariable(
      this,
      "public_tls_certificate_key",
      {
        type: "string",
        description: "TLS Certificate Private Key Secret ARN",
      }
    );
    // Validate that the Certificate Key exists
    new DataAwsSecretsmanagerSecretVersion(this, "publicTlsCertificate", {
      secretId: publicTlsCertificateKey.stringValue,
    });

    let keyName = "";

    if (userVariables.sshKeyEnabled) {
      const keyNameVar = new TerraformVariable(this, "zilla_plus_ssh_key", {
        type: "string",
        description:
          "Name of an existing EC2 KeyPair to enable SSH access to the instances",
      });
      keyName = keyNameVar.stringValue;
    }

    let zillaTelemetryContent = "";
    let bindingTelemetryContent = "";

    if (!userVariables.cloudwatchDisabled) {
      const defaultLogGroupName = `${id}-group`;
      const defaultMetricNamespace = `${id}-namespace`;

      const cloudWatchLogsGroup = new TerraformVariable(
        this,
        "cloudwatch_logs_group",
        {
          type: "string",
          description:
            "The Cloud Watch log group Zilla Plush should publish logs",
          default: defaultLogGroupName,
        }
      );

      const cloudWatchMetricsNamespace = new TerraformVariable(
        this,
        "cloudwatch_metrics_namespace",
        {
          type: "string",
          description:
            "The Cloud Watch metrics namespace Zilla Plush should publish metrics",
          default: defaultMetricNamespace,
        }
      );

      new CloudwatchLogGroup(this, "loggroup", {
        name: cloudWatchLogsGroup.stringValue,
      });

      const logsSection = `
        logs:
          group: ${cloudWatchLogsGroup.stringValue}
          stream: events`;

      const metricsSection = `
        metrics:
          namespace: ${cloudWatchMetricsNamespace.stringValue}`;

      zillaTelemetryContent = `
telemetry:
  metrics:
    - stream.active.received
    - stream.active.sent
    - stream.opens.received
    - stream.opens.sent
    - stream.data.received
    - stream.data.sent
    - stream.errors.received
    - stream.errors.sent
    - stream.closes.received
    - stream.closes.sent
  exporters:
    stdout_logs_exporter:
      type: stdout
    aws0:
      type: aws-cloudwatch
      options:
${logsSection}
${metricsSection}`;

      bindingTelemetryContent = `
    telemetry:
      metrics:
        - stream.*`;
    }

    const instanceType = new TerraformVariable(
      this,
      "zilla_plus_instance_type",
      {
        type: "string",
        default: "t3.small",
        description: "Zilla Plus EC2 instance type",
      }
    );
    instanceType.addValidation({
      condition: `${Fn.contains(
        instanceTypes.instanceTypes,
        instanceType.stringValue
      )}`,
      errorMessage: "must be a valid EC2 instance type.",
    });

    const ami = new dataAwsAmi.DataAwsAmi(this, "LatestAmi", {
      mostRecent: true,
      filter: [
        {
          name: "product-code",
          values: ["ca5mgk85pjtbyuhtfluzisgzy"],
        },
        {
          name: "is-public",
          values: ["true"],
        },
      ],
    });

    const nlb = new Lb(this, `NetworkLoadBalancer-${id}`, {
      name: "network-load-balancer",
      loadBalancerType: "network",
      internal: false,
      subnets: subnetIds,
      enableCrossZoneLoadBalancing: true,
    });

    const nlbTargetGroup = new LbTargetGroup(this, "NLBTargetGroup", {
      name: "nlb-target-group",
      port: publicPort.value,
      protocol: "TCP",
      vpcId: vpc.id,
    });

    new LbListener(this, "NLBListener", {
      loadBalancerArn: nlb.arn,
      port: publicPort.value,
      protocol: "TCP",
      defaultAction: [
        {
          type: "forward",
          targetGroupArn: nlbTargetGroup.arn,
        },
      ],
    });

    const externalHost = [
      "b-#.",
      Fn.element(Fn.split("*.", publicWildcardDNS.stringValue), 1),
    ].join("");

    const internalHost = [
      "b-#.",
      Fn.element(Fn.split("*.", mskWildcardDNS), 1),
    ].join("");

    const zillaYamlContent = `
name: public
vaults:
  secure:
    type: aws
${zillaTelemetryContent}
bindings:
  tcp_server:
    type: tcp
    kind: server
    options:
      host: 0.0.0.0
      port: ${publicPort}
${bindingTelemetryContent}
    exit: tls_server
  tls_server:
    type: tls
    kind: server
    vault: secure
    options:
      keys:
      - ${publicTlsCertificateKey.stringValue}
${tlsTrust}
    routes:
    - exit: kafka_proxy
      when:
      - authority: '${publicWildcardDNS.stringValue}'
  kafka_proxy:
    type: kafka-proxy
    kind: proxy
    options:
      external:
        host: '${externalHost}'
        port: ${publicPort}
      internal:
        host: '${internalHost}'
        port:  ${mskPort}
    exit: tls_client
  tls_client:
    type: tls
    kind: client
    vault: secure
    options:
${tlsClientSigners}
      trustcacerts: true
    exit: tcp_client
  tcp_client:
    type: tcp
    kind: client
    options:
      host: '*'
      port: ${mskPort}
    routes:
    - when:
      - authority: '${mskWildcardDNS}'
    `;

    const cfnHupConfContent = `
[main]
stack=${id}
region=${region}
    `;

    const cfnAutoReloaderConfContent = `
[cfn-auto-reloader-hook]
triggers=post.update
path=Resources.ZillaPlusLaunchTemplate.Metadata.AWS::CloudFormation::Init
action=/opt/aws/bin/cfn-init -v --stack ${id} --resource ZillaPlusLaunchTemplate --region ${region}
runas=root
    `;

    const userData = `#!/bin/bash -xe
yum update -y aws-cfn-bootstrap
cat <<EOF > /etc/zilla/zilla.yaml
${zillaYamlContent}
EOF

chown ec2-user:ec2-user /etc/zilla/zilla.yaml

mkdir /etc/cfn
cat <<EOF > /etc/cfn/cfn-hup.conf
${cfnHupConfContent}
EOF

chown root:root /etc/cfn/cfn-hup.conf
chmod 0400 /etc/cfn/cfn-hup.conf

mkdir /etc/cfn/hooks.d
cat <<EOF > /etc/cfn/hooks.d/cfn-auto-reloader.conf
${cfnAutoReloaderConfContent}
EOF

chown root:root /etc/cfn/hooks.d/cfn-auto-reloader.conf
chmod 0400 /etc/cfn/hooks.d/cfn-auto-reloader.conf

systemctl enable cfn-hup
systemctl start cfn-hup
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent
systemctl enable zilla-plus
systemctl start zilla-plus

    `;

    const ZillaPlusLaunchTemplate = new launchTemplate.LaunchTemplate(
      this,
      "ZillaPlusLaunchTemplate",
      {
        imageId: ami.imageId,
        instanceType: instanceType.stringValue,
        networkInterfaces: [
          {
            associatePublicIpAddress: "true",
            deviceIndex: 0,
            securityGroups: zillaPlusSecurityGroups,
          },
        ],
        iamInstanceProfile: {
          name: zillaPlusRole,
        },
        keyName: keyName,
        userData: Fn.base64encode(userData),
      }
    );

    new autoscalingGroup.AutoscalingGroup(this, "ZillaPlusGroup", {
      vpcZoneIdentifier: subnetIds,
      launchTemplate: {
        id: ZillaPlusLaunchTemplate.id,
      },
      minSize: 1,
      maxSize: 5,
      desiredCapacity: zillaPlusCapacity.numberValue,
      targetGroupArns: [nlbTargetGroup.arn],
    });

    new TerraformOutput(this, "NetworkLoadBalancerOutput", {
      description: "Public DNS name of newly created NLB for Zilla Plus",
      value: nlb.dnsName,
    });
  }
}

const app = new App();
new ZillaPlusSecurePublicAccessStack(app, "secure-public-access");
app.synth();
