-- The identity pin list moves to the account-records store (docs/plans/
-- account-records.md, slice 4): the one record of the scope `pins`. No data
-- moves (the wipe).
DROP TABLE identity_pins;
