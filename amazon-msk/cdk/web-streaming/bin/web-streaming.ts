#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { WebStreamingStack } from '../lib/web-streaming-stack';

const app = new cdk.App();
new WebStreamingStack(app, 'WebStreamingStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION
}});
