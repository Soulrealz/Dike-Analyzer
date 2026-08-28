//! dike-core must contain no Solana/Anchor vocabulary. If this fails, the seam
//! has leaked and a Solidity port would require changing core.
use std::fs;

#[test]
fn core_contains_no_solana_identifiers() {
    let banned = [
        "anchor", "solana", "Signer<", "AccountInfo", "UncheckedAccount",
        "has_one", "invoke_signed", "pubkey", "Pubkey", "spl_",
    ];
    let mut offenders = Vec::new();
    for entry in walkdir::WalkDir::new("src") {
        let entry = entry.unwrap();
        if entry.path().extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = fs::read_to_string(entry.path()).unwrap();
        for (i, line) in text.lines().enumerate() {
            // Doc comments may reference the domain; code may not.
            if line.trim_start().starts_with("//") {
                continue;
            }
            for word in banned {
                if line.contains(word) {
                    offenders.push(format!("{}:{}: {}", entry.path().display(), i + 1, word));
                }
            }
        }
    }
    assert!(offenders.is_empty(), "seam leak:\n{}", offenders.join("\n"));
}
