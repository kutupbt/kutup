DROP FUNCTION kutup_account_federates(uuid);
ALTER TABLE users DROP COLUMN federation;
DROP TABLE consents;
DROP TABLE document_acknowledgements;
DROP TABLE legal_documents;
