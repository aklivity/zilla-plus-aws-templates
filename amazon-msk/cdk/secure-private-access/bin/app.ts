#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { MskProvisionedClusterStack } from '../lib/MskProvisionedClusterStack';
import { SecurePrivateAccessStack } from '../lib/SecurePrivateAccessStack';
import { SecurePrivateAccessClientStack } from '../lib/SecurePrivateAccessClientStack';
import { SecurePublicAccessStack } from '../lib/SecurePublicAccessStack';

const app = new cdk.App();
const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION
};

new MskProvisionedClusterStack(app, 'MskProvisionedCluster', { env: env });
new SecurePrivateAccessStack(app, 'SecurePrivateAccess', { env: env });
new SecurePrivateAccessClientStack(app, 'SecurePrivateAccessClient', { env: env });
new SecurePublicAccessStack(app, 'SecurePublicAccess', { env: env });
