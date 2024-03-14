import {
  type CloudFrontHeaders,
  type CloudFrontRequest,
  type CloudFrontRequestEvent,
  type CloudFrontResultResponse
} from 'aws-lambda'

import * as axios from 'axios'
import {
  GetSecretValueCommand,
  SecretsManagerClient
} from '@aws-sdk/client-secrets-manager'
import * as cookie from 'cookie'
import * as crypto from 'crypto'
import { type JwtPayload, decode, verify } from 'jsonwebtoken'
import {
  type ParsedUrlQuery,
  parse as parseQueryString,
  stringify as stringifyQueryString
} from 'querystring'

interface Config {
  CALLBACK_PATH: string
  CLIENT_ID: string
  CLIENT_SECRET: string
  DOMAIN: string
  DISCOVERY_DOCUMENT: string
}

let discoveryDocument: {
  jwks_uri: string
  authorization_endpoint: string
  token_endpoint: string
}
let jwks: {
  keys: Array<{ kid: string }>
}
let config: Config

const errorPageStyle = `
<style type="text/css">
  html {
    width: 100%;
    height: 100%;
  }
  body {
    background-color: #ffffff;
    width: 100%;
    height: 100%;
    color:#000000;
    text-align: center;
    padding: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: "Open Sans", Arial, sans-serif;
  }
  h1 {
    font-family: inherit;
    font-weight: 500;
    line-height: 1.1;
    color: inherit;
    font-size: 36px;
  }
  h1 small {
    font-size: 68%;
    font-weight: 400;
    line-height: 1;
    color: #777;
  }
</style>
`

/**
 * handle is the starting point for the lambda.
 *
 * @param {Object} event is the event that initiates the handler
 * @param {AWS.Context} ctx is the aws lambda context
 * @param {(Error, any) => undefined} cb is the aws callback to signal completion.  This is used
 * instead of the async method because it has more predictable behavior.
 * @param {object} setDependencies is a function that sets the dependencies  If this is undefined
 * (as it will be in production) the setDependencies function in the module will set the
 * dependencies.  If this value is specified (as it will be in tests) then deps will be
 * overwritten with the specified dependencies.
 */
export const handler = async (event: CloudFrontRequestEvent): Promise<CloudFrontResultResponse | CloudFrontRequest> => {
  try {
    await loadConfig()
    await loadDiscoveryDocument()
    await setJwks()
    return await authenticate(event)
  } catch (err: unknown) {
    console.error(
      err instanceof Error ? err.message : 'unknown error',
      { event },
      err
    )
    return internalServerErrorResponse()
  }
}

async function authenticate (evt: CloudFrontRequestEvent): Promise<CloudFrontResultResponse | CloudFrontRequest> {
  const { request } = evt.Records[0].cf
  const { headers, querystring } = request
  const queryString = parseQueryString(querystring)
  console.log(`requested uri ${request.uri}`)
  if (request.uri.startsWith(config.CALLBACK_PATH)) {
    console.log('callback from OIDC provider received')
    if (queryString.error !== undefined) {
      return handleInvalidQueryString(queryString)
    }
    if (
      queryString.code === undefined ||
      queryString.code === null ||
      typeof queryString.code !== 'string'
    ) {
      return unauthorizedResponse('No Code Found', '', '')
    }
    const state =
      typeof queryString.state === 'string' ? queryString.state : ''
    return await getNewJwtResponse(state, queryString.code, headers)
  }
  if ('cookie' in headers && 'TOKEN' in cookie.parse(headers.cookie[0].value)) {
    return await getVerifyJwtResponse(request, headers)
  }
  return redirectToOidc(request)
}

export async function jwkToPem (webKey: crypto.JsonWebKey): Promise<string> {
  const pubKey: crypto.KeyObject = crypto.createPublicKey({
    key: webKey,
    format: 'jwk'
  })

  return pubKey.export({ format: 'pem', type: 'pkcs1' }).toString()
}

async function verifyToken (token: string, nonce?: string): Promise<void> {
  const decodedToken = decode(token, {
    complete: true
  })
  const rawPem = jwks.keys.filter((k) => k.kid === decodedToken?.header.kid)[0]
  if (rawPem === undefined) {
    throw new Error('unable to find expected pem in jwks keys')
  }
  const pem = await jwkToPem(rawPem)
  verify(token, pem, { algorithms: ['RS256'], nonce })
}

async function getVerifyJwtResponse (
  request: CloudFrontRequest,
  headers: CloudFrontHeaders
): Promise<CloudFrontResultResponse | CloudFrontRequest> {
  try {
    await verifyToken(cookie.parse(headers.cookie[0].value).TOKEN)
    return request
  } catch (err) {
    if (!(err instanceof Error)) {
      return unauthorizedResponse('Unauthorized.', 'Unknown error', '')
    }
    switch (err.name) {
      case 'TokenExpiredError':
        console.warn(
          'token expired, redirecting to OIDC provider',
          undefined,
          err
        )
        return redirectToOidc(request)
      case 'JsonWebTokenError':
        console.warn('jwt error, unauthorized', undefined, err)
        return unauthorizedResponse('Json Web Token Error', err.message, '')
      default:
        console.warn('unknown JWT error, unauthorized', undefined, err)
        return unauthorizedResponse('Unauthorized.', 'User is not permitted')
    }
  }
}

async function getNewJwtResponse (
  state: string,
  code: string,
  headers: CloudFrontHeaders
): Promise<CloudFrontResultResponse> {
  const tokenRequest = {
    client_id: config.CLIENT_ID,
    client_secret: config.CLIENT_SECRET,
    redirect_uri: `https://${config.DOMAIN}/_callback`,
    grant_type: 'authorization_code',
    code
  }
  const idToken = await getToken(tokenRequest)
  try {
    const nonce = headers.cookie?.[0]?.value !== undefined
      ? cookie.parse(headers.cookie?.[0]?.value).NONCE
      : undefined
    console.log(`expected nonce ${nonce}`)
    // await verifyToken(idToken, nonce);
    await verifyToken(idToken)
    return redirectToRequestedPage(state, idToken)
  } catch (err) {
    console.warn('unable to get valid token', err)
    return unauthorizedResponse('Unable to get token')
  }
}

async function getToken (tokenRequest: {
  client_id: string
  client_secret: string
  redirect_uri: string
  grant_type: string
  code: string
}): Promise<string> {
  const response = await axios.default.post(
    discoveryDocument.token_endpoint,
    tokenRequest,
    { headers: { 'content-type': 'application/x-www-form-urlencoded' } }
  )
  return response.data.id_token
}

function handleInvalidQueryString (queryString: ParsedUrlQuery): CloudFrontResultResponse {
  const errors: {
    [key: string]: string | undefined
    invalid_request: string
    unauthorized_client: string
    access_denied: string
    unsupported_response_type: string
    invalid_scope: string
    server_error: string
    temporarily_unavailable: string
  } = {
    invalid_request: 'Invalid Request',
    unauthorized_client: 'Unauthorized Client',
    access_denied: 'Access Denied',
    unsupported_response_type: 'Unsupported Response Type',
    invalid_scope: 'Invalid Scope',
    server_error: 'Server Error',
    temporarily_unavailable: 'Temporarily Unavailable'
  }

  let error = ''
  let errorDescription = ''
  let errorUri = ''

  if (typeof queryString.error === 'string') {
    if (errors[queryString.error] != null) {
      error = errors[queryString.error] ?? queryString.error
    } else {
      error = queryString.error ?? ''
    }
  } else {
    error = queryString.error?.join('.') ?? ''
  }

  if (typeof queryString.error_description === 'string') {
    errorDescription = queryString.error_description ?? ''
  } else {
    errorDescription = queryString.error_description?.join('.') ?? ''
  }

  if (typeof queryString.error_uri === 'string') {
    errorUri = queryString.error_uri ?? ''
  } else {
    errorUri = queryString.error_uri?.join('.') ?? ''
  }

  return unauthorizedResponse(error, errorDescription, errorUri)
}

async function fetchConfigFromSecretsManager (): Promise<Config> {
  const secretId = process.env.CONFIG_SECRET_ID
  const secretsManagerClient = new SecretsManagerClient({
    region: 'eu-central-1'
  })
  const secret = await secretsManagerClient.send(
    new GetSecretValueCommand({ SecretId: secretId })
  )
  if (secret.SecretString === undefined) {
    throw Error('invalid config secret')
  }
  return JSON.parse(secret.SecretString) as Config
}

async function loadConfig (): Promise<void> {
  if (config === undefined) {
    config = await fetchConfigFromSecretsManager()
  }
}

async function loadDiscoveryDocument (): Promise<void> {
  if (discoveryDocument === undefined) {
    discoveryDocument = (await axios.default.get(config.DISCOVERY_DOCUMENT))
      .data
  }
}

async function setJwks (): Promise<void> {
  if (jwks === undefined) {
    if (
      (discoveryDocument.jwks_uri === undefined ||
        discoveryDocument.jwks_uri === null)
    ) {
      throw new Error('Unable to find JWK in discovery document')
    }
    jwks = (await axios.default.get(discoveryDocument.jwks_uri)).data
  }
}

function getNonceAndHash (): { nonce: string, hash: string } {
  const nonce = crypto.randomBytes(32).toString('hex')
  const hash = crypto.createHmac('sha256', nonce).digest('hex')
  return { nonce, hash }
}

function redirectToRequestedPage (state: string, token: string): CloudFrontResultResponse {
  const decodedToken = decode(token) as JwtPayload
  const response = {
    status: '302',
    statusDescription: 'Found',
    body: 'ID token retrieved.',
    headers: {
      location: [
        {
          key: 'Location',
          value: state
        }
      ],
      'set-cookie': [
        {
          key: 'Set-Cookie',
          value: cookie.serialize('TOKEN', token, {
            path: '/',
            maxAge: decodedToken.exp
          })
        },
        {
          key: 'Set-Cookie',
          value: cookie.serialize('NONCE', '', {
            path: '/',
            expires: new Date(1970, 1, 1, 0, 0, 0, 0)
          })
        }
      ]
    }
  }
  return response
}

function redirectToOidc (request: CloudFrontRequest): CloudFrontResultResponse {
  const { nonce, hash } = getNonceAndHash()
  console.log(`redirect to oidc with nonce ${nonce}`)
  const authRequest = {
    nonce,
    state: request.uri,
    client_id: config.CLIENT_ID,
    response_type: 'code',
    scope: 'openid',
    redirect_uri: `https://${config.DOMAIN}/_callback`
  }

  return {
    status: '302',
    statusDescription: 'Found',
    body: 'Redirecting to OIDC provider',
    headers: {
      location: [
        {
          key: 'Location',
          value: `${
            discoveryDocument.authorization_endpoint
          }?${stringifyQueryString(authRequest)}`
        }
      ],
      'set-cookie': [
        {
          key: 'Set-Cookie',
          value: cookie.serialize('TOKEN', '', {
            path: '/',
            expires: new Date(1970, 1, 1, 0, 0, 0, 0)
          })
        },
        {
          key: 'Set-Cookie',
          value: cookie.serialize('NONCE', hash, {
            path: '/',
            httpOnly: true
          })
        }
      ]
    }
  }
}

function unauthorizedResponse (
  error: string,
  errorDescription?: string,
  errorUri?: string
): CloudFrontResultResponse {
  const body = `<!doctype html>
  <html lang="en">
    <head>
      <meta charset="utf-8" />
      <title>401 - Unauthorized</title>
      ${errorPageStyle}
    </head>
    <body>
      <div><h1>${error} <small>Error 401</small></h1><p class="lead">${
          errorDescription ?? ''
        }</p><p>${errorUri ?? ''}</p></div>
    </body>
  </html>  
  `

  return {
    body,
    status: '401',
    statusDescription: 'Unauthorized',
    headers: {
      'set-cookie': [
        {
          key: 'Set-Cookie',
          value: cookie.serialize('TOKEN', '', {
            path: '/',
            expires: new Date(1970, 1, 1, 0, 0, 0, 0)
          })
        },
        {
          key: 'Set-Cookie',
          value: cookie.serialize('NONCE', '', {
            path: '/',
            expires: new Date(1970, 1, 1, 0, 0, 0, 0)
          })
        }
      ]
    }
  }
}

function internalServerErrorResponse (): CloudFrontResultResponse {
  const body = `<!doctype html>
  <html lang="en">
    <head>
      <meta charset="utf-8" />
      <title>500 - Internal Server Error</title>
      ${errorPageStyle}
    </head>
    <body>
      <div class="cover">
        <h1>Internal Server Error <small>Error 500</small></h1>
      </div>
    </body>
  </html>  
  `

  return { status: '500', statusDescription: 'Internal Server Error', body }
}
