// @vitest-environment jsdom
import { fireEvent, render, screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { MlsGroupSecurityDetails } from './MlsGroupSecurityDetails'
import type {
  LocalMlsConversationRecord,
  MlsAuthorityPolicyInspection,
} from './types'

const ownerId = '11'.repeat(32)
const ownerPublicKey = 'ERERERERERERERERERERERERERERERERERERERERERE='
const controlKeyId = '22'.repeat(32)
const controlPublicKey = 'IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI='
const identityKeyId = '33'.repeat(32)
const identityPublicKey = 'MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM='

function group(): LocalMlsConversationRecord {
  const authorization = { policyVersion: 1 as const, sequence: 1, applicationSenders: 1 as const }
  const cryptographic = {
    policyVersion: 1 as const,
    sequence: 1,
    suite: 2 as const,
    requiredPrivateControlExtension: 0xff4b,
    maximumPastEpochs: 2 as const,
    anonymousDeliveryRequired: true as const,
    paddingBlockBytes: 1024 as const,
    maximumApplicationPlaintextBytes: 1024 * 1024,
  }
  return {
    request: {
      genesis: {
        protocolVersion: 1,
        conversationId: '11111111-1111-4111-8111-111111111111',
        incarnation: 1,
        mlsGroupId: 'BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=',
        kind: 'group',
        suite: 2,
        rosterCommitment: '44'.repeat(32),
        memberCount: 1,
        authoritySet: {
          sequence: 1,
          authorities: [{
            domain: 'alpha.example',
            keyId: controlKeyId,
            publicKey: controlPublicKey,
          }],
          requiredQuorum: 1,
        },
        ownerSet: {
          sequence: 1,
          owners: [{ ownerId, publicKey: ownerPublicKey }],
          requiredQuorum: 1,
        },
        initialEpoch: 0,
        createdAt: 1_700_000_000,
      },
      members: [{
        address: { username: 'alice', server: 'alpha.example' },
        isAdmin: true,
        ownerId,
      }],
    },
    status: 'active',
    serverGenesisHash: '55'.repeat(32),
    lastFinalizedHeight: 0,
    lastFinalizedEpoch: 0,
    currentRoster: [{
      address: { username: 'alice', server: 'alpha.example' },
      isAdmin: true,
      ownerId,
    }],
    currentAuthoritySet: {
      sequence: 1,
      authorities: [{
        domain: 'alpha.example',
        keyId: controlKeyId,
        publicKey: controlPublicKey,
      }],
      requiredQuorum: 1,
    },
    currentOwnerSet: {
      sequence: 1,
      owners: [{ ownerId, publicKey: ownerPublicKey }],
      requiredQuorum: 1,
    },
    genesisAuthorizationPolicy: authorization,
    genesisCryptographicPolicy: cryptographic,
    currentAuthorizationPolicy: authorization,
    currentCryptographicPolicy: cryptographic,
  }
}

function inspection(matches = true): MlsAuthorityPolicyInspection {
  return {
    domain: 'alpha.example',
    currentMatchesGroupPin: matches,
    unavailable: false,
    history: {
      domain: 'alpha.example',
      policies: [{
        sequence: 2,
        previousPolicyHash: '66'.repeat(32),
        policyHash: '77'.repeat(32),
        payloadDigest: '88'.repeat(32),
        issuedAt: 1_700_000_000,
        federationIdentityGeneration: 3,
        federationIdentityKeyId: identityKeyId,
        federationIdentityPublicKey: identityPublicKey,
        policy: {
          policyVersion: 1,
          canonicalDomain: 'alpha.example',
          suite: 2,
          anonymousDeliverySuite: 1,
          controlSigningKeyId: controlKeyId,
          controlSigningPublicKey: controlPublicKey,
          acceptsGroupOrdering: true,
          maximumGroupMembers: 1000,
          maximumAuthorities: 64,
          maximumControlPayloadBytes: 1024 * 1024,
          pendingMessageRequests: {
            maximumMessages: 32,
            maximumCiphertextBytes: 1024 * 1024,
            expirySeconds: 2_592_000,
          },
          abuseLimits: {
            anonymousAttemptsPerIpMinute: 60,
            capabilityBundleRequestsPerMinute: 30,
            sealedSendsPerCapabilityMinute: 120,
            sealedSendsPerCapabilityDay: 10_000,
            federatedSealedSendsPerOriginMinute: 600,
            maximumEnvelopesPerRequest: 32,
            maximumRequestBytes: 1024 * 1024,
          },
        },
      }],
    },
  }
}

describe('MlsGroupSecurityDetails', () => {
  it('renders complete owner, group-pin, identity, and live policy fingerprints', () => {
    render(
      <MlsGroupSecurityDetails
        group={group()}
        authorityPolicies={[inspection()]}
        loading={false}
      />,
    )

    expect(
      screen.getByTestId('chat-group-owner-fingerprint-alice@alpha.example'),
    ).toHaveTextContent(ownerId)
    expect(
      screen.getByTestId('chat-group-authority-pin-alpha.example'),
    ).toHaveTextContent(controlKeyId)
    fireEvent.click(
      within(screen.getByTestId('chat-group-authority-policy-alpha.example'))
        .getByText('Exact authenticated service policy'),
    )
    expect(
      screen.getByTestId('chat-group-authority-identity-fingerprint-alpha.example'),
    ).toHaveTextContent(identityKeyId)
    expect(
      screen.getByTestId('chat-group-authority-policy-fingerprint-alpha.example'),
    ).toHaveTextContent(controlKeyId)
    expect(
      screen.getByTestId('chat-group-authority-policy-sequence-alpha.example'),
    ).toHaveTextContent('2')
    const authority = screen.getByTestId('chat-group-authority-alpha.example')
    expect(within(authority).getByText('Authenticated; matches group pin')).toBeVisible()
    expect(within(authority).getByText('0x0002')).toBeVisible()
    expect(within(authority).getByText('1000')).toBeVisible()
    expect(
      screen.getByTestId('chat-group-authority-history-alpha.example-2'),
    ).toHaveTextContent('77'.repeat(32))
  })

  it('retains exact group pins and exposes unavailable live verification', () => {
    render(
      <MlsGroupSecurityDetails
        group={group()}
        authorityPolicies={[{
          domain: 'alpha.example',
          currentMatchesGroupPin: false,
          unavailable: true,
        }]}
        loading={false}
      />,
    )

    expect(screen.getByText('Verification unavailable')).toBeVisible()
    expect(screen.getByText(/exact group pin above remains in force/i)).toBeVisible()
    expect(
      screen.getByTestId('chat-group-authority-pin-alpha.example'),
    ).toHaveTextContent(controlKeyId)
  })

  it('shows authenticated key divergence without replacing the group pin', () => {
    const changed = inspection(false)
    changed.history!.policies[0].policy.controlSigningKeyId = '99'.repeat(32)
    render(
      <MlsGroupSecurityDetails
        group={group()}
        authorityPolicies={[changed]}
        loading={false}
      />,
    )

    expect(
      screen.getByText('Authenticated current policy differs from group pin'),
    ).toBeVisible()
    fireEvent.click(
      within(screen.getByTestId('chat-group-authority-policy-alpha.example'))
        .getByText('Exact authenticated service policy'),
    )
    expect(
      screen.getByTestId('chat-group-authority-pin-alpha.example'),
    ).toHaveTextContent(controlKeyId)
    expect(
      screen.getByTestId('chat-group-authority-policy-fingerprint-alpha.example'),
    ).toHaveTextContent('99'.repeat(32))
  })
})
