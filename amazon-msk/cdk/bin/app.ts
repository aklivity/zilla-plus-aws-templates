#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { SecurePrivateAccessStack } from '../lib/SecurePrivateAccessStack';
import { SecurePrivateAccessClientStack } from '../lib/SecurePrivateAccessClientStack';
import { SecurePublicAccessStack } from '../lib/SecurePublicAccessStack';
import { MskServerlessClusterStack } from '../lib/MskServerlessClusterStack';
import { MskProvisionedClusterStack } from '../lib/MskProvisionedClusterStack';
import { IotIngestAndControlStack } from '../lib/IotIngestAndControlStack';
import { WebStreamingStack } from '../lib/WebStreamingStack';

const app = new cdk.App();
const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION
};

if (app.node.tryGetContext('MskServerlessCluster')) {
  new MskServerlessClusterStack(app, 'MskServerlessCluster', { env: env });
}

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

if (app.node.tryGetContext('IotIngestAndControl')) {
  new IotIngestAndControlStack(app, 'IotIngestAndControl', { env: env });
}

if (app.node.tryGetContext('WebStreaming')) {
  new WebStreamingStack(app, 'WebStreaming', { env: env });
}
