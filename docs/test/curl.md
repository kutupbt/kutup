# API Test Commands (curl)

Base URL: `http://localhost` (nginx proxy)

> Note: file content and metadata are E2E-encrypted by the browser client.
> These curl commands test the API transport layer with dummy base64 payloads.

---

## 1. Register

```sh
curl -s -X POST http://localhost/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "test@example.com",
    "loginKeyHash": "dGVzdGhhc2g=",
    "encryptedMasterKey": "ZW5jbWFzdGVya2V5",
    "masterKeyNonce": "bm9uY2U=",
    "encryptedRecoveryKey": "ZW5jcmVj",
    "recoveryKeyNonce": "cmVjbm9uY2U=",
    "encryptedPrivateKey": "ZW5jcHJpdg==",
    "privateKeyNonce": "cHJpdm5vbmNl",
    "publicKey": "cHVia2V5",
    "kdfSalt": "a2Rmc2FsdA==",
    "loginKeySalt": "bG9naW5zYWx0"
  }' | jq
```

## 2. Login

```sh
TOKEN=$(curl -s -X POST http://localhost/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com","loginKeyHash":"dGVzdGhhc2g="}' \
  | jq -r '.accessToken')
echo "TOKEN=$TOKEN"
```

## 3. Create collection

```sh
COLL_ID=$(curl -s -X POST http://localhost/api/collections/ \
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
curl -s http://localhost/api/collections/ \
  -H "Authorization: Bearer $TOKEN" | jq
```

## 5. Set folder color

```sh
curl -s -X PATCH http://localhost/api/collections/$COLL_ID/color \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"color": "blue"}' -w "\nHTTP %{http_code}\n"
```

## 6. Rename folder (re-encrypt name client-side; here dummy values)

```sh
curl -s -X PUT http://localhost/api/collections/$COLL_ID \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "encryptedName": "bmV3bmFtZQ==",
    "nameNonce": "bmV3bm9uY2U="
  }' | jq
```

## 7. Upload file (dummy encrypted blob)

```sh
FILE_ID=$(curl -s -X POST http://localhost/api/files/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "collectionId=$COLL_ID" \
  -F "encryptedMetadata=ZW5jbWV0YQ==" \
  -F "metadataNonce=bWV0YW5vbmNl" \
  -F "encryptedFileKey=ZW5jZmlsZWtleQ==" \
  -F "fileKeyNonce=ZmlsZWtleW5vbmNl" \
  -F "file=@/dev/urandom;filename=encrypted;type=application/octet-stream" \
  | jq -r '.id')
echo "FILE_ID=$FILE_ID"
```

> For a real test file use a small file: replace `/dev/urandom` with a local path.

## 8. List files in collection

```sh
curl -s http://localhost/api/collections/$COLL_ID/files \
  -H "Authorization: Bearer $TOKEN" | jq
```

## 9. Download file

```sh
curl -s http://localhost/api/files/$FILE_ID/download \
  -H "Authorization: Bearer $TOKEN" \
  -o /tmp/downloaded_encrypted
echo "saved to /tmp/downloaded_encrypted"
```

## 10. Delete file

```sh
curl -s -X DELETE http://localhost/api/files/$FILE_ID \
  -H "Authorization: Bearer $TOKEN" -w "\nHTTP %{http_code}\n"
```

## 11. Delete collection

```sh
curl -s -X DELETE http://localhost/api/collections/$COLL_ID \
  -H "Authorization: Bearer $TOKEN" -w "\nHTTP %{http_code}\n"
```
