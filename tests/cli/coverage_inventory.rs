//! Keep evidence references live without treating case counts as coverage.
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    schema_version: u32,
    invariants: Vec<Invariant>,
    errors: BTreeMap<String, ErrorEvidence>,
    independent_cases: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Invariant {
    id: String,
    claim: String,
    cases: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorEvidence {
    cases: Vec<String>,
    gap: String,
}
fn codes(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if key == "code" {
                    if let Some(code) = value.as_str() {
                        out.insert(code.to_owned());
                    }
                } else {
                    codes(value, out);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                codes(value, out);
            }
        }
        _ => (),
    }
}
#[test]
fn coverage_inventory_references_existing_assertions_and_provenance() {
    let inventory: Inventory =
        serde_json::from_str(include_str!("../coverage-inventory.json")).unwrap();
    let suite: Value = serde_json::from_str(include_str!("../cases.json")).unwrap();
    let manifest: Value = serde_json::from_str(include_str!("../fixtures/manifest.json")).unwrap();
    let cases: BTreeMap<_, _> = suite["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["id"].as_str().unwrap(), c))
        .collect();
    assert_eq!(inventory.schema_version, 1);
    let mut ids = BTreeSet::new();
    for invariant in &inventory.invariants {
        assert!(ids.insert(&invariant.id));
        assert!(!invariant.claim.is_empty() && !invariant.cases.is_empty());
        for id in &invariant.cases {
            assert!(cases.contains_key(id.as_str()), "missing case {id}");
        }
    }
    let mut observed = BTreeSet::new();
    for case in cases.values() {
        codes(&case["expect"]["json"], &mut observed);
    }
    for code in observed {
        assert!(
            inventory.errors.contains_key(&code),
            "new error needs inventory: {code}"
        );
    }
    for (code, evidence) in &inventory.errors {
        let _: rssig::domain::ErrorCode =
            serde_json::from_value(Value::String(code.clone())).unwrap();
        assert_eq!(evidence.cases.is_empty(), !evidence.gap.is_empty());
        for id in &evidence.cases {
            let mut asserted = BTreeSet::new();
            codes(&cases[id.as_str()]["expect"]["json"], &mut asserted);
            assert!(asserted.contains(code), "{id} does not assert {code}");
        }
    }
    for id in &inventory.independent_cases {
        let case = cases[id.as_str()];
        let file = case["input"].as_str().unwrap();
        let artifact = manifest["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["file"] == file)
            .expect("independent evidence must be in manifest");
        assert!(artifact.get("provenance").is_some() || artifact.get("description").is_some());
    }
}
