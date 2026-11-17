-- The Chat group list and contact list move to the account-records store
-- (docs/plans/account-records.md, slice 5): the scopes `chatGroups` and
-- `chatContacts`. No data moves (the wipe).
DROP TABLE chat_group_list;
DROP TABLE chat_contact_list;
