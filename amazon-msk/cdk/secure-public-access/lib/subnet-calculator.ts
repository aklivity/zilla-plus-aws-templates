var ip = require('ip');

function cidrBlocksOverlap(cidr1: string, cidr2: string): boolean {
    const range1 = ip.cidrSubnet(cidr1);
    const range2 = ip.cidrSubnet(cidr2);

    const start1 = ip.toLong(range1.firstAddress);
    const end1 = ip.toLong(range1.lastAddress);
    const start2 = ip.toLong(range2.firstAddress);
    const end2 = ip.toLong(range2.lastAddress);

    return start1 <= end2 && start2 <= end1;
}

export function findAvailableCidrBlocks(vpcCidrBlock: string, subnetCidrBlocks: string[], subnetMask: number, requiredCount: number = 2): string[] {
    const availableCidrs: string[] = [];
    const vpcRange = ip.cidrSubnet(vpcCidrBlock);

    // Start searching within the VPC range, block by block
    let currentBlock = ip.fromLong(ip.toLong(vpcRange.networkAddress));

    while (availableCidrs.length < requiredCount) {
        const candidateCidr = `${currentBlock}/${subnetMask}`;
        if (!subnetCidrBlocks.some(subnet => cidrBlocksOverlap(candidateCidr, subnet))) {
            availableCidrs.push(candidateCidr);
        }

        // Increment to the next block based on the subnet mask
        const increment = Math.pow(2, 32 - subnetMask);
        currentBlock = ip.fromLong(ip.toLong(currentBlock) + increment);

        // Break if we go beyond the VPC range
        if (ip.toLong(currentBlock) > ip.toLong(vpcRange.lastAddress)) {
            break;
        }
    }

    if (availableCidrs.length < requiredCount) {
        throw new Error("Not enough available CIDR blocks in the specified VPC range.");
    }

    return availableCidrs;
}
