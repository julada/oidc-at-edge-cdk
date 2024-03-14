#!/usr/bin/env node
/* eslint-disable no-new */
import 'source-map-support/register'
import * as cdk from 'aws-cdk-lib'
import { CloudfrontOidcCognitoStack } from './cloudfront-oidc-cognito-stack'

const app = new cdk.App()
new CloudfrontOidcCognitoStack(app, 'CloudfrontOidcCognitoStack', {
  env: {
    region: 'eu-central-1'
  },
  appName: app.node.tryGetContext('appName'),
  hostedZoneId: app.node.tryGetContext('hostedZoneId'),
  hostedZoneDomain: app.node.tryGetContext('hostedZoneDomain')
})
