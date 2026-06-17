use crate::codec::package::{build_package_from_value, verify_package_value};
use anyhow::{Context, Result};
use std::fs;

const DEFAULT_TARGET_FIELDS: &[&str] = &[
    "extraction.fields.parcel_id",
    "parcel_id",
    "workflow_id",
    "snapshot_id",
    "source",
    "mode",
    "case_id",
    "procedure_id",
];

pub fn run(input_path: &str, target_field: Option<&str>) -> Result<()> {
    let content = fs::read_to_string(input_path)
        .with_context(|| format!("Failed to read input file: {}", input_path))?;

    let input_value: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse input JSON: {}", input_path))?;

    let package = if input_value.get("schema").and_then(|v| v.as_str()) == Some("SPARK-V7-PACKAGE")
    {
        input_value
    } else {
        build_package_from_value(&input_value)?
    };

    let target_path = resolve_target_path(&package, target_field)?;

    let mut detected_count = 0;

    // --- Case 01: Payload field mutation ---
    {
        let mut tampered = package.clone();
        if let Some(val) = get_payload_value_mut(&mut tampered, &target_path) {
            *val = serde_json::Value::String(format!("{}-MUTATED", val.as_str().unwrap_or("")));
        } else {
            return Err(missing_target_error(&target_path, &tampered));
        }
        if verify_package_value(&tampered).is_err() {
            println!("case 01/05 payload field mutation: ok");
            detected_count += 1;
        } else {
            println!("case 01/05 payload field mutation: FAILED (tamper not detected)");
        }
    }

    // --- Case 02: Payload field deletion ---
    {
        let mut tampered = package.clone();
        if !remove_payload_value(&mut tampered, &target_path) {
            return Err(missing_target_error(&target_path, &tampered));
        }
        if verify_package_value(&tampered).is_err() {
            println!("case 02/05 payload field deletion: ok");
            detected_count += 1;
        } else {
            println!("case 02/05 payload field deletion: FAILED (tamper not detected)");
        }
    }

    // --- Case 03: payload_sha256 mutation ---
    {
        let mut tampered = package.clone();
        let hash_val = tampered
            .get_mut("sidecar")
            .and_then(|s| s.get_mut("payload_sha256"));
        if let Some(val) = hash_val {
            *val = serde_json::Value::String(mutate_hash(val.as_str().unwrap_or("")));
        } else {
            return Err(anyhow::anyhow!("payload_sha256 not found in sidecar"));
        }
        if verify_package_value(&tampered).is_err() {
            println!("case 03/05 payload_sha256 mutation: ok");
            detected_count += 1;
        } else {
            println!("case 03/05 payload_sha256 mutation: FAILED (tamper not detected)");
        }
    }

    // --- Case 04: integrity_hash mutation ---
    {
        let mut tampered = package.clone();
        let hash_val = tampered.get_mut("integrity_hash");
        if let Some(val) = hash_val {
            *val = serde_json::Value::String(mutate_hash(val.as_str().unwrap_or("")));
        } else {
            return Err(anyhow::anyhow!("integrity_hash not found in package"));
        }
        if verify_package_value(&tampered).is_err() {
            println!("case 04/05 integrity_hash mutation: ok");
            detected_count += 1;
        } else {
            println!("case 04/05 integrity_hash mutation: FAILED (tamper not detected)");
        }
    }

    // --- Case 05: tool sequence mutation ---
    {
        let mut tampered = package.clone();
        let seq_val = tampered
            .get_mut("sidecar")
            .and_then(|s| s.get_mut("tool_sequence"));
        if let Some(val) = seq_val {
            if let serde_json::Value::Array(ref mut arr) = val {
                arr.push(serde_json::Value::String("malicious.tool".to_string()));
            } else {
                return Err(anyhow::anyhow!("tool_sequence is not an array"));
            }
        } else {
            return Err(anyhow::anyhow!("tool_sequence not found in sidecar"));
        }
        if verify_package_value(&tampered).is_err() {
            println!("case 05/05 tool sequence mutation: ok");
            detected_count += 1;
        } else {
            println!("case 05/05 tool sequence mutation: FAILED (tamper not detected)");
        }
    }

    println!("adversarial: {}/5 detected", detected_count);

    if detected_count == 5 {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Adversarial suite did not detect all tamper cases (detected {}/5)",
            detected_count
        ))
    }
}

fn resolve_target_path(package: &serde_json::Value, target_field: Option<&str>) -> Result<String> {
    let payload = package
        .get("payload")
        .ok_or_else(|| anyhow::anyhow!("Missing payload"))?;

    if let Some(target) = target_field {
        if get_value_by_dot_path(payload, target).is_some_and(is_scalar_string) {
            return Ok(target.to_string());
        }
        return Err(missing_target_error(target, package));
    }

    for target in DEFAULT_TARGET_FIELDS {
        if get_value_by_dot_path(payload, target).is_some_and(is_scalar_string) {
            return Ok((*target).to_string());
        }
    }

    if let Some((path, _)) = collect_scalar_string_fields(payload)
        .into_iter()
        .find(|(path, _)| !path.contains('.'))
    {
        return Ok(path);
    }

    Err(anyhow::anyhow!(
        "No target field found in payload. Available scalar fields: {}",
        available_scalar_fields(payload)
    ))
}

fn missing_target_error(target: &str, package: &serde_json::Value) -> anyhow::Error {
    let available = package
        .get("payload")
        .map(available_scalar_fields)
        .unwrap_or_else(|| "(none)".to_string());
    anyhow::anyhow!(
        "Target field '{}' not found in payload. Available scalar fields: {}",
        target,
        available
    )
}

fn get_payload_value_mut<'a>(
    package: &'a mut serde_json::Value,
    path: &str,
) -> Option<&'a mut serde_json::Value> {
    let mut current = package.get_mut("payload")?;
    for part in path.split('.') {
        current = current.as_object_mut()?.get_mut(part)?;
    }
    Some(current)
}

fn remove_payload_value(package: &mut serde_json::Value, path: &str) -> bool {
    let Some((parent_path, field)) = path.rsplit_once('.') else {
        return package
            .get_mut("payload")
            .and_then(|p| p.as_object_mut())
            .and_then(|m| m.remove(path))
            .is_some();
    };

    let Some(parent) = get_payload_value_mut(package, parent_path) else {
        return false;
    };
    parent
        .as_object_mut()
        .and_then(|m| m.remove(field))
        .is_some()
}

fn get_value_by_dot_path<'a>(
    value: &'a serde_json::Value,
    path: &str,
) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for part in path.split('.') {
        if part.is_empty() {
            return None;
        }
        current = current.as_object()?.get(part)?;
    }
    Some(current)
}

fn collect_scalar_string_fields(value: &serde_json::Value) -> Vec<(String, String)> {
    let mut fields = Vec::new();
    collect_scalar_string_fields_recursive(value, "", &mut fields);
    fields.sort_by(|left, right| left.0.cmp(&right.0));
    fields
}

fn collect_scalar_string_fields_recursive(
    value: &serde_json::Value,
    current_path: &str,
    fields: &mut Vec<(String, String)>,
) {
    if let serde_json::Value::Object(map) = value {
        for (key, child) in map {
            let path = if current_path.is_empty() {
                key.clone()
            } else {
                format!("{}.{}", current_path, key)
            };
            if let Some(value) = child.as_str() {
                fields.push((path, value.to_string()));
            } else {
                collect_scalar_string_fields_recursive(child, &path, fields);
            }
        }
    }
}

fn available_scalar_fields(payload: &serde_json::Value) -> String {
    let fields: Vec<String> = collect_scalar_string_fields(payload)
        .into_iter()
        .map(|(path, _)| path)
        .collect();
    if fields.is_empty() {
        "(none)".to_string()
    } else {
        fields.join(", ")
    }
}

fn is_scalar_string(value: &serde_json::Value) -> bool {
    value.as_str().is_some()
}

fn mutate_hash(value: &str) -> String {
    if value.is_empty() {
        return "0".to_string();
    }
    let (prefix, last) = value.split_at(value.len() - 1);
    let replacement = if last == "0" { "1" } else { "0" };
    format!("{}{}", prefix, replacement)
}
