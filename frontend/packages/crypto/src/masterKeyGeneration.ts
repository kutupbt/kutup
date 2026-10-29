// The account's master-key generation (docs/plans/w6-key-hierarchy.md §2):
// every account envelope names the master key it holds or was sealed under.
// 1 until master-key rotation exists; a search for this name finds every
// seal that rotation will have to give the account's current generation.
export const MASTER_KEY_GENERATION = 1
