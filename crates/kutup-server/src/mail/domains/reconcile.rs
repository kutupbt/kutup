//! Stalwart follows the database (docs/plans/mail-custom-domains.md §10):
//! every usable custom domain has a Stalwart `Domain` and, once its DKIM was
//! good, a `DkimSignature` with the active selector; nothing else of ours
//! exists there. Only domains tagged as Kutup's (their description) and the
//! signatures under them are ever touched, so `MAIL_DOMAIN`'s own are left
//! alone. A signature has no description, so the domain row records which
//! Stalwart object signs with which key.
//!
//! [`plan`] is pure; [`apply`] runs a plan through a [`Stalwart`] (the
//! management API, or a fake in tests). A single runner holds the advisory
//! lock, so two never interleave.

use axum::async_trait;

/// The description every object of ours carries, with the domain row's id.
pub const TAG: &str = "kutup-custom-domain:";

pub fn tag(domain_id: &uuid::Uuid) -> String {
    format!("{TAG}{domain_id}")
}

/// The domain row a Stalwart domain of ours belongs to.
fn tagged_id(description: &str) -> Option<uuid::Uuid> {
    description.strip_prefix(TAG)?.parse().ok()
}

/// A domain as the database wants it in Stalwart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wanted {
    pub id: uuid::Uuid,
    pub name: String,
    /// The signature to sign with: `None` until DKIM was good once, or while
    /// it is in `ERROR` or `DELEGATED`.
    pub signature: Option<Signature>,
    /// The signature the row says Stalwart has: its object and key.
    pub recorded: Option<Recorded>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recorded {
    pub object_id: String,
    pub key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub selector: String,
    /// The active key, as Stalwart takes it (PKCS#8 PEM).
    pub private_key_pem: String,
    /// Which key it is, so a rotation replaces the signature.
    pub key_id: String,
}

/// An object of Stalwart's, as listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StalwartDomain {
    pub object_id: String,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StalwartSignature {
    pub object_id: String,
    pub domain_object_id: String,
    pub selector: String,
}

/// One step of a plan, in the order to run it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    DeleteSignature {
        object_id: String,
    },
    DeleteDomain {
        object_id: String,
    },
    CreateDomain {
        wanted: uuid::Uuid,
        name: String,
    },
    /// For a domain created in this plan or already there.
    CreateSignature {
        wanted: uuid::Uuid,
        signature: Signature,
    },
}

/// The steps that make Stalwart's tagged objects match `wanted`. Deletes go
/// first (signatures before their domains), then creates (domains before
/// their signatures). A signature is kept only when the row records it
/// with the wanted key, so a new key replaces it.
pub fn plan(
    wanted: &[Wanted],
    domains: &[StalwartDomain],
    signatures: &[StalwartSignature],
) -> Vec<Step> {
    let ours: Vec<(&StalwartDomain, uuid::Uuid)> = domains
        .iter()
        .filter_map(|d| tagged_id(&d.description).map(|id| (d, id)))
        .collect();
    let mut deletes = Vec::new();
    let mut creates = Vec::new();
    let mut kept_domains = Vec::new();
    for (domain, id) in &ours {
        match wanted.iter().find(|w| w.id == *id && w.name == domain.name) {
            Some(_) => kept_domains.push((domain.object_id.clone(), *id)),
            None => {
                for signature in signatures
                    .iter()
                    .filter(|s| s.domain_object_id == domain.object_id)
                {
                    deletes.push(Step::DeleteSignature {
                        object_id: signature.object_id.clone(),
                    });
                }
                deletes.push(Step::DeleteDomain {
                    object_id: domain.object_id.clone(),
                });
            }
        }
    }
    for want in wanted {
        let existing = kept_domains.iter().find(|(_, id)| *id == want.id);
        let current: Vec<&StalwartSignature> = match existing {
            Some((object_id, _)) => signatures
                .iter()
                .filter(|s| &s.domain_object_id == object_id)
                .collect(),
            None => {
                creates.push(Step::CreateDomain {
                    wanted: want.id,
                    name: want.name.clone(),
                });
                Vec::new()
            }
        };
        // Kept only when the row's record names it, with the wanted key and
        // selector: anything else under the domain goes.
        let keep = match (&want.signature, &want.recorded) {
            (Some(signature), Some(recorded)) if recorded.key_id == signature.key_id => current
                .iter()
                .find(|s| s.object_id == recorded.object_id && s.selector == signature.selector)
                .map(|s| s.object_id.clone()),
            _ => None,
        };
        for signature in current {
            if Some(&signature.object_id) != keep.as_ref() {
                deletes.push(Step::DeleteSignature {
                    object_id: signature.object_id.clone(),
                });
            }
        }
        if let (Some(signature), None) = (&want.signature, &keep) {
            creates.push(Step::CreateSignature {
                wanted: want.id,
                signature: signature.clone(),
            });
        }
    }
    // Signatures' deletes before domains', whatever order they were found in.
    deletes.sort_by_key(|step| matches!(step, Step::DeleteDomain { .. }));
    creates.sort_by_key(|step| matches!(step, Step::CreateSignature { .. }));
    deletes.into_iter().chain(creates).collect()
}

/// Stalwart's management API, as the reconcile needs it.
#[async_trait]
pub trait Stalwart: Send + Sync {
    async fn domains(&self) -> anyhow::Result<Vec<StalwartDomain>>;
    async fn signatures(&self) -> anyhow::Result<Vec<StalwartSignature>>;
    async fn create_domain(&self, name: &str, description: &str) -> anyhow::Result<String>;
    async fn delete_domain(&self, object_id: &str) -> anyhow::Result<()>;
    async fn create_signature(
        &self,
        domain_object_id: &str,
        selector: &str,
        private_key_pem: &str,
    ) -> anyhow::Result<String>;
    async fn delete_signature(&self, object_id: &str) -> anyhow::Result<()>;
}

/// What a run changed that the rows must record: a domain's new signature
/// (its object and key), or none any more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub steps: usize,
    pub recorded: Vec<(uuid::Uuid, Option<Recorded>)>,
}

/// Lists what is there, plans, and runs the plan. Stops at the first error:
/// the next run starts from what is there then (a created signature not yet
/// recorded is deleted and made again).
pub async fn apply(stalwart: &dyn Stalwart, wanted: &[Wanted]) -> anyhow::Result<Applied> {
    let domains = stalwart.domains().await?;
    let signatures = stalwart.signatures().await?;
    let steps = plan(wanted, &domains, &signatures);
    let mut created: Vec<(uuid::Uuid, String)> = Vec::new();
    let mut recorded: Vec<(uuid::Uuid, Option<Recorded>)> = Vec::new();
    let object_of = |id: &uuid::Uuid, created: &[(uuid::Uuid, String)]| {
        created
            .iter()
            .find(|(c, _)| c == id)
            .map(|(_, o)| o.clone())
            .or_else(|| {
                domains
                    .iter()
                    .find(|d| tagged_id(&d.description) == Some(*id))
                    .map(|d| d.object_id.clone())
            })
    };
    for step in &steps {
        match step {
            Step::DeleteSignature { object_id } => stalwart.delete_signature(object_id).await?,
            Step::DeleteDomain { object_id } => stalwart.delete_domain(object_id).await?,
            Step::CreateDomain { wanted, name } => {
                let object = stalwart.create_domain(name, &tag(wanted)).await?;
                created.push((*wanted, object));
            }
            Step::CreateSignature { wanted, signature } => {
                let domain = object_of(wanted, &created)
                    .ok_or_else(|| anyhow::anyhow!("no Stalwart domain for {wanted}"))?;
                let object_id = stalwart
                    .create_signature(&domain, &signature.selector, &signature.private_key_pem)
                    .await?;
                recorded.push((
                    *wanted,
                    Some(Recorded {
                        object_id,
                        key_id: signature.key_id.clone(),
                    }),
                ));
            }
        }
    }
    // A wanted domain without a signature records none.
    for want in wanted {
        if want.signature.is_none() && want.recorded.is_some() {
            recorded.push((want.id, None));
        }
    }
    Ok(Applied {
        steps: steps.len(),
        recorded,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Stalwart as a list of objects.
    #[derive(Default)]
    struct FakeStalwart {
        domains: Mutex<Vec<StalwartDomain>>,
        signatures: Mutex<Vec<StalwartSignature>>,
        next: Mutex<u32>,
    }

    impl FakeStalwart {
        fn id(&self) -> String {
            let mut next = self.next.lock().unwrap();
            *next += 1;
            format!("o{next}")
        }
    }

    #[async_trait]
    impl Stalwart for FakeStalwart {
        async fn domains(&self) -> anyhow::Result<Vec<StalwartDomain>> {
            Ok(self.domains.lock().unwrap().clone())
        }
        async fn signatures(&self) -> anyhow::Result<Vec<StalwartSignature>> {
            Ok(self.signatures.lock().unwrap().clone())
        }
        async fn create_domain(&self, name: &str, description: &str) -> anyhow::Result<String> {
            let object_id = self.id();
            self.domains.lock().unwrap().push(StalwartDomain {
                object_id: object_id.clone(),
                name: name.into(),
                description: description.into(),
            });
            Ok(object_id)
        }
        async fn delete_domain(&self, object_id: &str) -> anyhow::Result<()> {
            let mut signatures = self.signatures.lock().unwrap();
            anyhow::ensure!(
                !signatures.iter().any(|s| s.domain_object_id == object_id),
                "a domain with signatures can't go"
            );
            signatures.retain(|s| s.domain_object_id != object_id);
            self.domains
                .lock()
                .unwrap()
                .retain(|d| d.object_id != object_id);
            Ok(())
        }
        async fn create_signature(
            &self,
            domain_object_id: &str,
            selector: &str,
            _private_key_pem: &str,
        ) -> anyhow::Result<String> {
            anyhow::ensure!(
                self.domains
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|d| d.object_id == domain_object_id),
                "no such domain"
            );
            let object_id = self.id();
            self.signatures.lock().unwrap().push(StalwartSignature {
                object_id: object_id.clone(),
                domain_object_id: domain_object_id.into(),
                selector: selector.into(),
            });
            Ok(object_id)
        }
        async fn delete_signature(&self, object_id: &str) -> anyhow::Result<()> {
            self.signatures
                .lock()
                .unwrap()
                .retain(|s| s.object_id != object_id);
            Ok(())
        }
    }

    /// The rows: each domain's wanted key and what it records.
    #[derive(Default)]
    struct Rows(std::collections::BTreeMap<uuid::Uuid, (String, Option<String>, Option<Recorded>)>);

    impl Rows {
        fn set(&mut self, id: uuid::Uuid, name: &str, key: Option<&str>) {
            let recorded = self.0.get(&id).and_then(|(_, _, r)| r.clone());
            self.0
                .insert(id, (name.into(), key.map(str::to_owned), recorded));
        }

        fn wanted(&self) -> Vec<Wanted> {
            self.0
                .iter()
                .map(|(id, (name, key, recorded))| Wanted {
                    id: *id,
                    name: name.clone(),
                    signature: key.as_ref().map(|key| Signature {
                        selector: "kutup1".into(),
                        private_key_pem: format!("pem-{key}"),
                        key_id: key.clone(),
                    }),
                    recorded: recorded.clone(),
                })
                .collect()
        }

        async fn run(&mut self, fake: &FakeStalwart) -> usize {
            let applied = apply(fake, &self.wanted()).await.unwrap();
            for (id, recorded) in applied.recorded {
                if let Some(row) = self.0.get_mut(&id) {
                    row.2 = recorded;
                }
            }
            applied.steps
        }
    }

    fn wanted(id: uuid::Uuid, name: &str) -> Wanted {
        Wanted {
            id,
            name: name.into(),
            signature: None,
            recorded: None,
        }
    }

    fn server_domain() -> StalwartDomain {
        StalwartDomain {
            object_id: "server".into(),
            name: "kutup.dev".into(),
            description: "the server's own".into(),
        }
    }

    #[tokio::test]
    async fn stalwart_follows_the_database_and_settles() {
        let fake = FakeStalwart::default();
        fake.domains.lock().unwrap().push(server_domain());
        let (a, b) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let mut rows = Rows::default();

        // A new domain, no DKIM yet; another with its key.
        rows.set(a, "a.example", None);
        rows.set(b, "b.example", Some("k1"));
        assert_eq!(rows.run(&fake).await, 3);
        assert_eq!(fake.domains.lock().unwrap().len(), 3);
        assert_eq!(fake.signatures.lock().unwrap().len(), 1);
        // Nothing to do the second time.
        assert_eq!(rows.run(&fake).await, 0);

        // a's DKIM turns good; b's key rotates: its signature is replaced.
        rows.set(a, "a.example", Some("k1"));
        rows.set(b, "b.example", Some("k2"));
        let before = rows.0[&b].2.clone().unwrap();
        assert_eq!(rows.run(&fake).await, 3);
        let after = rows.0[&b].2.clone().unwrap();
        assert_eq!(after.key_id, "k2");
        assert_ne!(after.object_id, before.object_id);
        assert_eq!(fake.signatures.lock().unwrap().len(), 2);
        assert_eq!(rows.run(&fake).await, 0);

        // A signature made but never recorded (a crash between) is replaced.
        rows.0.get_mut(&a).unwrap().2 = None;
        assert_eq!(rows.run(&fake).await, 2);
        assert_eq!(fake.signatures.lock().unwrap().len(), 2);

        // b goes inactive: its signature, then its domain; the server's own
        // domain is never touched.
        rows.0.remove(&b);
        assert_eq!(rows.run(&fake).await, 2);
        let names: Vec<String> = fake
            .domains
            .lock()
            .unwrap()
            .iter()
            .map(|d| d.name.clone())
            .collect();
        assert_eq!(
            names,
            vec!["kutup.dev".to_string(), "a.example".to_string()]
        );
        rows.0.clear();
        assert_eq!(rows.run(&fake).await, 2);
        assert_eq!(*fake.domains.lock().unwrap(), vec![server_domain()]);
    }

    #[test]
    fn untagged_objects_are_never_in_a_plan() {
        let signature = StalwartSignature {
            object_id: "s".into(),
            domain_object_id: "server".into(),
            selector: "202601e".into(),
        };
        assert!(plan(&[], &[server_domain()], &[signature]).is_empty());
    }

    #[test]
    fn a_renamed_row_is_replaced_not_kept() {
        let id = uuid::Uuid::new_v4();
        let there = StalwartDomain {
            object_id: "o1".into(),
            name: "old.example".into(),
            description: tag(&id),
        };
        let steps = plan(&[wanted(id, "new.example")], &[there], &[]);
        assert_eq!(
            steps,
            vec![
                Step::DeleteDomain {
                    object_id: "o1".into()
                },
                Step::CreateDomain {
                    wanted: id,
                    name: "new.example".into()
                },
            ]
        );
    }
}
