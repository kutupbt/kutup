# API Test Commands (curl)

Base URL: `https://localhost:38443` (bundled Nginx proxy). The examples use
`--insecure` only for the local self-signed development certificate. Never
disable certificate verification against a production server.

> Note: file content and metadata are E2E-encrypted by the browser client.
> These curl commands test the API transport layer. Account envelopes below
> are structurally valid V1 values bound to `test@example.com`; their plaintext
> and keys are deliberately zero test material.

---

## 1. Register

```sh
curl --insecure --silent -X POST https://localhost:38443/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "test@example.com",
    "username": "testuser",
    "loginKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "masterKeyEnvelope": "S1VUUEFFMQAAAQEAABB0ZXN0QGV4YW1wbGUuY29tJHfwtPzRJ9xNvol1mHoKXyjNjJ25+8qlAAAAMJFcjAe0u9Km+mtjVuVv+zV6d28wIw5oexWbRggZMjQ4Wz0fgvwwBLT1s4ZmSeAtYg==",
    "recoveryKeyEnvelope": "S1VUUEFFMQAAAQIAABB0ZXN0QGV4YW1wbGUuY29tUF4VvGfWEX+5PwSlg+YDzPwKYZYe+MVpAAAAMH0nCNyq3eXxgQsONFv2wH8ja/djLUC0hOq7uqkUv48u4wXY9WacGyftLHZcQgiOjA==",
    "drivePrivateKeyEnvelope": "S1VUUEFFMQAAAQMAABB0ZXN0QGV4YW1wbGUuY29tNwFHm9kxpJtOcycqYIydmU7+QorcrCLdAAAAMG6oIs6rNKAk6wV2lPOKuxDnQOE7yiMjj4moaEjMpR5kNUykANhaVK0MRG08hMUE2w==",
    "publicKey": "cHVia2V5",
    "accountProtectionSuite": 1,
    "accountProtectionSalt": "AAAAAAAAAAAAAAAAAAAAAA==",
    "argonMemoryKib": 65536,
    "argonIterations": 3,
    "argonParallelism": 1,
    "recoveryProof": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
  }' | jq
```

## 2. Login

```sh
TOKEN=$(curl --insecure --silent -X POST https://localhost:38443/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com","loginKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}' \
  | jq -r '.accessToken')
echo "TOKEN=$TOKEN"
```

## 3. Create collection

```sh
COLL_ID=$(curl --insecure --silent -X POST https://localhost:38443/api/collections/ \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "encryptedName": "ZW5jbmFtZQ==",
    "nameNonce": "bmFtZW5vbmNl",
    "encryptedKey": "ZW5ja2V5",
    "encryptedKeyNonce": "a2V5bm9uY2U=",
    "parentCollectionId": null
  }' | jq -r '.id')
echo "COLL_ID=$COLL_ID"
```

## 4. List collections

```sh
curl --insecure --silent https://localhost:38443/api/collections/ \
  -H "Authorization: Bearer $TOKEN" | jq
```

## 5. Set folder color

```sh
curl --insecure --silent -X PATCH https://localhost:38443/api/collections/$COLL_ID/color \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"color": "blue"}' -w "\nHTTP %{http_code}\n"
```

## 6. Rename folder (client-generated authenticated envelope)

Set `NAME_ENVELOPE` to a valid next-revision `DriveEnvelopeV1` produced by a
Kutup client. Arbitrary base64 is intentionally rejected.

```sh
curl --insecure --silent -X PUT https://localhost:38443/api/collections/$COLL_ID \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"nameEnvelope\":\"$NAME_ENVELOPE\",\"nameRevision\":2}" | jq
```

## 7. Upload file

The file UUID and envelopes must be created together by the Rust/WASM or CLI
crypto implementation. Set `FILE_ID`, `METADATA_ENVELOPE`, and
`FILE_KEY_ENVELOPE` from that client output; dummy values cannot pass the
server's purpose/object/collection/epoch checks.

```sh
STORED_FILE_ID=$(curl --insecure --silent -X POST https://localhost:38443/api/files/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "fileId=$FILE_ID" \
  -F "collectionId=$COLL_ID" \
  -F "metadataEnvelope=$METADATA_ENVELOPE" \
  -F "fileKeyEnvelope=$FILE_KEY_ENVELOPE" \
  -F "file=@/dev/urandom;filename=encrypted;type=application/octet-stream" \
  | jq -r '.id')
test "$STORED_FILE_ID" = "$FILE_ID"
```

> For a real test file use a small file: replace `/dev/urandom` with a local path.

## 8. List files in collection

```sh
curl --insecure --silent https://localhost:38443/api/collections/$COLL_ID/files \
  -H "Authorization: Bearer $TOKEN" | jq
```

## 9. Download file

```sh
curl --insecure --silent https://localhost:38443/api/files/$FILE_ID/download \
  -H "Authorization: Bearer $TOKEN" \
  -o /tmp/downloaded_encrypted
echo "saved to /tmp/downloaded_encrypted"
```

## 10. Delete file

```sh
curl --insecure --silent -X DELETE https://localhost:38443/api/files/$FILE_ID \
  -H "Authorization: Bearer $TOKEN" -w "\nHTTP %{http_code}\n"
```

## 11. Delete collection

```sh
curl --insecure --silent -X DELETE https://localhost:38443/api/collections/$COLL_ID \
  -H "Authorization: Bearer $TOKEN" -w "\nHTTP %{http_code}\n"
```

## 12. Inspect the federation control plane (admin)

Set `ADMIN_TOKEN` to an administrator access token. The projection should show
one shared identity plus Chat/Drive operational counts; it must not contain a
signing seed or plaintext Drive capability.

```sh
curl --insecure --silent https://localhost:38443/api/admin/federation \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  | jq '{serverName, features, operational, peers}'
```

For a pinned domain, inspect immutable public identity history and retry that
peer through the common resolver:

```sh
PEER=friend.example
curl --insecure --silent "https://localhost:38443/api/admin/federation/peers/$PEER/evidence" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq

curl --insecure --silent -X POST https://localhost:38443/api/admin/federation/peers/retry \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"domains\":[\"$PEER\"]}" | jq
```

Export only federation audit events:

```sh
curl --insecure --silent 'https://localhost:38443/api/admin/activity/export?actionPrefix=federation.&limit=5000' \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -o /tmp/kutup-federation-audit.csv
```
