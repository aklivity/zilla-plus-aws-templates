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

if (app.node.tryGetContext('MskProvisionedCluster')) {
  new MskProvisionedClusterStack(app, 'MskProvisionedCluster', { env: env });
}

if (app.node.tryGetContext('SecurePrivateAccess')) {
  new SecurePrivateAccessStack(app, 'SecurePrivateAccess', { env: env });
}

if (app.node.tryGetContext('SecurePrivateAccessClient')) {
  new SecurePrivateAccessClientStack(app, 'SecurePrivateAccessClient', { env: env });
}

if (app.node.tryGetContext('SecurePublicAccess')) {
  new SecurePublicAccessStack(app, 'SecurePublicAccess', { env: env });
}
