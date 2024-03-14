/* eslint-disable no-new */
import { SecretValue } from 'aws-cdk-lib'
import { experimental } from 'aws-cdk-lib/aws-cloudfront'
import { Effect, PolicyStatement } from 'aws-cdk-lib/aws-iam'
import { Code, Runtime } from 'aws-cdk-lib/aws-lambda'
import { RetentionDays } from 'aws-cdk-lib/aws-logs'
import { Secret } from 'aws-cdk-lib/aws-secretsmanager'
import { type Construct } from 'constructs'
import { mkdirSync, readFileSync, writeFileSync } from 'fs'
import path = require('path')

export class OIDCAtEdge extends experimental.EdgeFunction {
  constructor (
    scope: Construct,
    id: string,
    props: {
      name: string
      oidcConfig: {
        CALLBACK_PATH?: SecretValue | string
        CLIENT_ID?: SecretValue | string
        CLIENT_SECRET?: SecretValue
        DOMAIN?: SecretValue | string
        DISCOVERY_DOCUMENT?: SecretValue | string
      }
    }
  ) {
    const secretId = props.name
    const code = readFileSync(path.join(__dirname, './lambda/dist/index.js'))
      .toString()
      .replace('process.env.CONFIG_SECRET_ID', `"${secretId}"`)
    mkdirSync('./cdk.out/edge-lambda', { recursive: true })
    writeFileSync('./cdk.out/edge-lambda/index.js', code)
    super(scope, id, {
      functionName: props.name,
      code: Code.fromAsset('./cdk.out/edge-lambda'),
      handler: 'index.handler',
      runtime: Runtime.NODEJS_LATEST,
      logRetention: RetentionDays.ONE_DAY
    })
    const secret = new Secret(this, `${id}-secret`, {
      secretName: props.name,
      secretObjectValue: {
        CALLBACK_PATH: typeof props.oidcConfig.CALLBACK_PATH === 'string' ? SecretValue.unsafePlainText(props.oidcConfig.CALLBACK_PATH) : props.oidcConfig.CALLBACK_PATH ?? SecretValue.unsafePlainText(''),
        CLIENT_ID: typeof props.oidcConfig.CLIENT_ID === 'string' ? SecretValue.unsafePlainText(props.oidcConfig.CLIENT_ID) : props.oidcConfig.CLIENT_ID ?? SecretValue.unsafePlainText(''),
        CLIENT_SECRET: props.oidcConfig.CLIENT_SECRET ?? SecretValue.unsafePlainText(''),
        DOMAIN: typeof props.oidcConfig.DOMAIN === 'string' ? SecretValue.unsafePlainText(props.oidcConfig.DOMAIN) : props.oidcConfig.DOMAIN ?? SecretValue.unsafePlainText(''),
        DISCOVERY_DOCUMENT: typeof props.oidcConfig.DISCOVERY_DOCUMENT === 'string' ? SecretValue.unsafePlainText(props.oidcConfig.DISCOVERY_DOCUMENT) : props.oidcConfig.DISCOVERY_DOCUMENT ?? SecretValue.unsafePlainText('')
      }
    })
    this.addToRolePolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['secretsmanager:GetSecretValue'],
        resources: [
          `${secret.secretArn}`,
          `${secret.secretArn}*`
        ]
      })
    )
  }
}
