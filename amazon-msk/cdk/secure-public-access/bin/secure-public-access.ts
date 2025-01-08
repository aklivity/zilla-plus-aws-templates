#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { ZillaPlusSecurePublicAccessStack } from '../lib/secure-public-access-stack';

const app = new cdk.App();
new ZillaPlusSecurePublicAccessStack(app, 'SecurePublicAccessStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION
}});
