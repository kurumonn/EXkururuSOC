use std::collections::HashSet;
use std::env;
use std::fs;
use std::time::Instant;

#[derive(Debug, Clone)]
struct FeedbackCount {
    source_product: String,
    source_ref: String,
    feedback_type: String,
    c: u32,
}

#[derive(Debug, Clone)]
struct ExistingKey {
    source_product: String,
    target_ref: String,
    candidate_type: String,
}

#[derive(Debug)]
struct BenchInput {
    rows: Vec<FeedbackCount>,
    existing: Vec<ExistingKey>,
    loops: usize,
    min_hits: u32,
}

#[derive(Debug)]
struct BenchOutput {
    loops: usize,
    min_hits: u32,
    row_count: usize,
    existing_count: usize,
    total_created: usize,
    elapsed_sec: f64,
    loops_per_sec: f64,
}

fn parse_input(content: &str) -> Result<BenchInput, String> {
    let mut rows = Vec::<FeedbackCount>::new();
    let mut existing = Vec::<ExistingKey>::new();
    let mut loops: usize = 0;
    let mut min_hits: u32 = 0;

    for (index, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('|').collect();
        if parts.is_empty() {
            continue;
        }
        match parts[0] {
            "CONFIG" => {
                if parts.len() != 3 {
                    return Err(format!("invalid CONFIG at line {}", index + 1));
                }
                loops = parts[1]
                    .parse::<usize>()
                    .map_err(|_| format!("invalid loops at line {}", index + 1))?;
                min_hits = parts[2]
                    .parse::<u32>()
                    .map_err(|_| format!("invalid min_hits at line {}", index + 1))?;
            }
            "ROW" => {
                if parts.len() != 5 {
                    return Err(format!("invalid ROW at line {}", index + 1));
                }
                let c = parts[4]
                    .parse::<u32>()
                    .map_err(|_| format!("invalid row count at line {}", index + 1))?;
                rows.push(FeedbackCount {
                    source_product: parts[1].to_string(),
                    source_ref: parts[2].to_string(),
                    feedback_type: parts[3].to_string(),
                    c,
                });
            }
            "EXISTING" => {
                if parts.len() != 4 {
                    return Err(format!("invalid EXISTING at line {}", index + 1));
                }
                existing.push(ExistingKey {
                    source_product: parts[1].to_string(),
                    target_ref: parts[2].to_string(),
                    candidate_type: parts[3].to_string(),
                });
            }
            _ => return Err(format!("unknown row type at line {}", index + 1)),
        }
    }

    if loops == 0 {
        return Err("missing or invalid CONFIG loops".to_string());
    }
    if min_hits == 0 {
        return Err("missing or invalid CONFIG min_hits".to_string());
    }

    Ok(BenchInput {
        rows,
        existing,
        loops,
        min_hits,
    })
}

fn create_base_keys(existing: &[ExistingKey]) -> HashSet<(String, String, String)> {
    let mut keys = HashSet::with_capacity(existing.len().saturating_mul(2));
    for item in existing {
        keys.insert((
            item.source_product.clone(),
            item.target_ref.clone(),
            item.candidate_type.clone(),
        ));
    }
    keys
}

fn run_once(
    rows: &[FeedbackCount],
    min_hits: u32,
    base_existing_keys: &HashSet<(String, String, String)>,
) -> usize {
    let mut existing_keys = base_existing_keys.clone();
    let mut created = 0usize;
    for row in rows {
        if row.c < min_hits {
            continue;
        }
        let candidate_type = format!("feedback_{}", row.feedback_type);
        let dedupe_key = (
            row.source_product.clone(),
            row.source_ref.clone(),
            candidate_type.clone(),
        );
        if existing_keys.contains(&dedupe_key) {
            continue;
        }

        // Python実装同等: 候補情報を都度シリアライズ相当の文字列処理を行う。
        let recommended_action = if row.feedback_type == "false_positive" {
            "reduce_score"
        } else {
            "raise_score"
        };
        let proposal = format!(
            "{{\"strategy\":\"feedback_driven_tuning\",\"feedback_type\":\"{}\",\"source_ref\":\"{}\",\"recommended_action\":\"{}\"}}",
            row.feedback_type, row.source_ref, recommended_action
        );
        let evidence = format!(
            "{{\"feedback_hits\":{},\"source_ref\":\"{}\",\"feedback_type\":\"{}\"}}",
            row.c, row.source_ref, row.feedback_type
        );
        let expected = if row.feedback_type == "false_positive" {
            "{\"false_positive_delta\":-0.1}".to_string()
        } else {
            "{\"false_positive_delta\":0.0}".to_string()
        };
        let _serialized_len = proposal.len() + evidence.len() + expected.len();

        existing_keys.insert(dedupe_key);
        created += 1;
    }
    created
}

fn run(input: BenchInput) -> BenchOutput {
    let base_existing_keys = create_base_keys(&input.existing);
    let started = Instant::now();
    let mut total_created = 0usize;
    for _ in 0..input.loops {
        total_created += run_once(&input.rows, input.min_hits, &base_existing_keys);
    }
    let elapsed_sec = started.elapsed().as_secs_f64();
    let loops_per_sec = if elapsed_sec > 0.0 {
        input.loops as f64 / elapsed_sec
    } else {
        0.0
    };
    BenchOutput {
        loops: input.loops,
        min_hits: input.min_hits,
        row_count: input.rows.len(),
        existing_count: input.existing.len(),
        total_created,
        elapsed_sec,
        loops_per_sec,
    }
}

fn plan_once(
    rows: &[FeedbackCount],
    min_hits: u32,
    base_existing_keys: &HashSet<(String, String, String)>,
) -> Vec<(String, String, String, u32)> {
    let mut existing_keys = base_existing_keys.clone();
    let mut created = Vec::<(String, String, String, u32)>::new();
    for row in rows {
        if row.c < min_hits {
            continue;
        }
        let candidate_type = format!("feedback_{}", row.feedback_type);
        let dedupe_key = (
            row.source_product.clone(),
            row.source_ref.clone(),
            candidate_type,
        );
        if existing_keys.contains(&dedupe_key) {
            continue;
        }
        existing_keys.insert(dedupe_key);
        created.push((
            row.source_product.clone(),
            row.source_ref.clone(),
            row.feedback_type.clone(),
            row.c,
        ));
    }
    created
}

fn main() {
    let mut args = env::args().skip(1);
    let Some(mode) = args.next() else {
        eprintln!("usage: rust_feedback_bench <bench|plan> <input_path>");
        std::process::exit(2);
    };
    let Some(input_path) = args.next() else {
        eprintln!("usage: rust_feedback_bench <bench|plan> <input_path>");
        std::process::exit(2);
    };

    let content = match fs::read_to_string(&input_path) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("failed_to_read_input: {error}");
            std::process::exit(2);
        }
    };

    let input = match parse_input(&content) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("failed_to_parse_input: {error}");
            std::process::exit(2);
        }
    };

    if mode == "bench" {
        let output = run(input);
        println!(
            "{{\"loops\":{},\"min_hits\":{},\"row_count\":{},\"existing_count\":{},\"total_created\":{},\"elapsed_sec\":{},\"loops_per_sec\":{}}}",
            output.loops,
            output.min_hits,
            output.row_count,
            output.existing_count,
            output.total_created,
            output.elapsed_sec,
            output.loops_per_sec
        );
        return;
    }

    if mode == "plan" {
        let base_existing_keys = create_base_keys(&input.existing);
        let created = plan_once(&input.rows, input.min_hits, &base_existing_keys);
        for (source_product, source_ref, feedback_type, hit_count) in created {
            println!(
                "CREATE|{}|{}|{}|{}",
                source_product, source_ref, feedback_type, hit_count
            );
        }
        return;
    }

    eprintln!("invalid_mode: {}", mode);
    std::process::exit(2);
}
