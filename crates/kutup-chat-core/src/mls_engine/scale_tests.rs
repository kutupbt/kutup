//! Production-capacity MLS tests kept separate from the functional suite.

use super::*;
use crate::SqliteChatDb;

const V1_GROUP_ACCOUNTS: usize = MAX_MLS_GROUP_ACCOUNTS;
const V1_DEVICES_PER_ACCOUNT: usize = MAX_MLS_DEVICES_PER_ACCOUNT;
const V1_GROUP_LEAVES: usize = V1_GROUP_ACCOUNTS * V1_DEVICES_PER_ACCOUNT;

#[test]
fn openmls_group_operates_with_256_accounts_and_2560_manifest_bound_leaves() {
    futures_executor::block_on(async {
        let creator_db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open_in_memory().unwrap());
        let creator = MlsClient::new(creator_db);
        let creator_public = creator.initialize("member0000@scale.test#1").await.unwrap();
        let creator_credential = VerifiedMlsCredential::new(
            "member0000@scale.test#1".into(),
            creator_public.credential_public_key,
        )
        .unwrap();
        let now = crate::clock::unix_millis() / 1000;

        let mut additions = Vec::with_capacity(V1_GROUP_LEAVES - 1);
        let mut expected_roster = Vec::with_capacity(V1_GROUP_LEAVES);
        expected_roster.push(creator_credential.clone());
        let mut final_recipient = None;

        for leaf_index in 1..V1_GROUP_LEAVES {
            let account_index = leaf_index / V1_DEVICES_PER_ACCOUNT;
            let device_id = (leaf_index % V1_DEVICES_PER_ACCOUNT) + 1;
            let identity = format!("member{account_index:04}@scale.test#{device_id}");
            let member_db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open_in_memory().unwrap());
            let member = MlsClient::new(member_db);
            let public = member.initialize(&identity).await.unwrap();
            let package = member
                .generate_key_package(1, device_id as u32, now, now + 86_400)
                .await
                .unwrap();
            let credential =
                VerifiedMlsCredential::new(identity, public.credential_public_key).unwrap();
            additions.push(VerifiedMlsKeyPackage {
                wire: package,
                credential: credential.clone(),
                anonymous_delivery_public_key: public.anonymous_delivery_public_key,
            });
            expected_roster.push(credential);
            if leaf_index + 1 == V1_GROUP_LEAVES {
                final_recipient = Some(member);
            }
        }

        let group_id = b"kutup-mls-v1-256-account-2560-leaf-scale";
        creator.create_group(group_id).await.unwrap();
        let pending = creator
            .prepare_add_members(group_id, &additions, now)
            .await
            .unwrap();
        assert_eq!((pending.epoch_before, pending.epoch_after), (0, 1));
        assert!(pending.commit.len() <= MAX_APPLICATION_BYTES);
        assert!(pending
            .welcome
            .as_ref()
            .is_some_and(|welcome| welcome.len() <= MAX_APPLICATION_BYTES));

        let final_recipient = final_recipient.expect("the 2,560th leaf is retained");
        let welcome = pending.welcome.as_deref().unwrap();
        let inspection = final_recipient
            .inspect_welcome(group_id, welcome)
            .await
            .unwrap();
        assert_eq!(inspection.epoch, 1);
        assert_eq!(inspection.claimed_members.len(), V1_GROUP_LEAVES);
        final_recipient
            .join_from_welcome(group_id, welcome, &expected_roster)
            .await
            .unwrap();
        creator
            .merge_pending_commit(group_id, &pending.commit_hash)
            .await
            .unwrap();

        assert_eq!(
            creator.group_devices(group_id).await.unwrap().len(),
            V1_GROUP_LEAVES
        );
        assert_eq!(
            final_recipient.group_devices(group_id).await.unwrap().len(),
            V1_GROUP_LEAVES
        );

        let outbound = creator
            .create_application_message(
                "e0aa3a3a-b9ce-485c-8d65-c024f03f64c4",
                *b"scale-group-v1!!",
                1,
                group_id,
                b"hello leaf 2560",
                now * 1000,
            )
            .await
            .unwrap();
        let decrypted = final_recipient
            .decrypt_application_message(group_id, &outbound.ciphertext, &creator_credential)
            .await
            .unwrap();
        assert_eq!(decrypted.plaintext, b"hello leaf 2560");
        assert_eq!(decrypted.epoch, 1);
    });
}
