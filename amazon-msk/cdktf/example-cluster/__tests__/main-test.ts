import "cdktf/lib/testing/adapters/jest";
import { Testing } from "cdktf";
import { ZillaPlusExampleMskCluster } from "../example-cluster-stack";
import { MskCluster } from "@cdktf/provider-aws/lib/msk-cluster";
import { SecurityGroup } from "@cdktf/provider-aws/lib/security-group";
import { Subnet } from "@cdktf/provider-aws/lib/subnet";
import { Vpc } from "@cdktf/provider-aws/lib/vpc";

describe("Zilla Plus Example MSK Cluster Test", () => {
  let output: string;

  beforeAll(() => {
    const app = Testing.app();
    const stack = new ZillaPlusExampleMskCluster(app, "test");
    output = Testing.synth(stack);
  });

  it("should have MSK cluster", async () => {
    expect(output).toHaveResourceWithProperties(MskCluster, {
      broker_node_group_info: {
        client_subnets: [
          "${aws_subnet.PrivateSubnet1.id}",
          "${aws_subnet.PrivateSubnet2.id}",
        ],
        instance_type: "kafka.t3.small",
        security_groups: ["${aws_security_group.MskSecurityGroup.id}"],
      },
      client_authentication: {
        sasl: {
          scram: true
        },
        unauthenticated: true,
      },
      cluster_name: "my-msk-cluster",
      encryption_info: {
        encryption_in_transit: {
          client_broker: "TLS_PLAINTEXT",
          in_cluster: true,
        },
      },
      kafka_version: "3.5.1",
      number_of_broker_nodes: 2,
    });
  });

  it("should have MSK security group", async () => {
    expect(output).toHaveResourceWithProperties(SecurityGroup, {
      description: "Security group for MSK cluster",
      egress: [
        {
          cidr_blocks: ["0.0.0.0/0"],
          description: null,
          from_port: 0,
          ipv6_cidr_blocks: null,
          prefix_list_ids: null,
          protocol: "tcp",
          security_groups: null,
          self: null,
          to_port: 65535,
        },
      ],
      ingress: [
        {
          cidr_blocks: ["0.0.0.0/0"],
          description: null,
          from_port: 9092,
          ipv6_cidr_blocks: null,
          prefix_list_ids: null,
          protocol: "tcp",
          security_groups: null,
          self: null,
          to_port: 9096,
        },
      ],
      tags: {
        Name: "msk-security-group",
      },
      vpc_id: "${aws_vpc.MskVpc.id}",
    });
  });

  it("should have subnet1", async () => {
    expect(output).toHaveResourceWithProperties(Subnet, {
      availability_zone: "${data.aws_region.CurrentRegion.name}a",
      cidr_block: "10.0.128.0/20",
      map_public_ip_on_launch: false,
      tags: {
        Name: "msk-private-subnet-1",
      },
      vpc_id: "${aws_vpc.MskVpc.id}",
    });
  });

  it("should have subnet2", async () => {
    expect(output).toHaveResourceWithProperties(Subnet, {
      availability_zone: "${data.aws_region.CurrentRegion.name}b",
      cidr_block: "10.0.144.0/20",
      map_public_ip_on_launch: false,
      tags: {
        Name: "msk-private-subnet-2",
      },
      vpc_id: "${aws_vpc.MskVpc.id}",
    });
  });

  it("should have VPC", async () => {
    expect(output).toHaveResourceWithProperties(Vpc, {
      cidr_block: "10.0.0.0/16",
      enable_dns_hostnames: true,
      enable_dns_support: true,
    });
  });
});
