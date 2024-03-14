import {
  Distribution,
  type DistributionProps,
  LambdaEdgeEventType,
  type OriginAccessIdentity
} from 'aws-cdk-lib/aws-cloudfront'
import { Construct } from 'constructs'
import { OIDCAtEdge } from './oidc-at-edge.construct'
import { type SecretValue } from 'aws-cdk-lib'
export class CloudfrontOIDC extends Construct {
  distribution: Distribution
  oai: OriginAccessIdentity
  constructor (
    scope: Construct,
    id: string,
    props: {
      distribution: DistributionProps
      oidcConfig: {
        CALLBACK_PATH?: SecretValue | string
        CLIENT_ID?: SecretValue | string
        CLIENT_SECRET?: SecretValue
        DISCOVERY_DOCUMENT?: SecretValue | string
      }
    }
  ) {
    super(scope, id)
    const authFn = new OIDCAtEdge(this, 'oidc-at-edge', {
      name: `${id}-oidc`,
      oidcConfig: {
        ...props.oidcConfig,
        DOMAIN: props.distribution.domainNames?.[0]
      }
    })
    if ((props.distribution.defaultBehavior.edgeLambdas?.find((e) => e.eventType === LambdaEdgeEventType.VIEWER_REQUEST)) != null) {
      throw Error('the viewer request lambda is reserved by the oidc function')
    }
    this.distribution = new Distribution(this, 'cloudfront-distribution', {
      defaultRootObject: 'index.html',
      ...props.distribution,
      defaultBehavior: {
        ...props.distribution.defaultBehavior,
        edgeLambdas: [
          ...(props.distribution.defaultBehavior.edgeLambdas ?? []),
          {
            functionVersion: authFn.currentVersion,
            eventType: LambdaEdgeEventType.VIEWER_REQUEST
          }
        ]
      }
    })
  }
}
