use anyhow::anyhow;
use bytes::{Bytes, BytesMut};
use clap::Parser;
use cpe::component::Component;
use cpe::cpe::Cpe as _;
use cpe::uri::Uri;
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressStyle};
use parking_lot::Mutex;
use rayon::prelude::*;
use spdx_rs::models::{PackageInformation, RelationshipType, SPDX};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::fs::File;
use std::io::stdout;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use walker_common::compression::Detector;

#[derive(Debug, PartialEq, Eq, clap::Parser)]
struct Cli {
    #[arg()]
    source: PathBuf,
    #[arg(short, long, default_value = ".json.bz2")]
    suffix: String,
    #[arg(short, long)]
    output: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    println!("Scanning: {}", cli.source.display());

    let mut entries = vec![];

    for entry in fs::read_dir(&cli.source)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.ends_with(&cli.suffix) {
            continue;
        }

        entries.push(entry.path());
    }

    let pb = ProgressBar::new(entries.len() as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta})",
        )?
        .progress_chars("#>-"),
    );

    let collector = Collector {
        extractors: vec![
            Box::new(|ctx: Context, doc: &mut Document| {
                doc.labels.insert(
                    "path".into(),
                    ctx.path
                        .file_name()
                        .unwrap_or(ctx.path.as_os_str())
                        .to_string_lossy()
                        .to_string(),
                );
            }),
            Box::new(Label(Cpe(|cpe| {
                vec![
                    ("cpe".into(), Some(cpe.to_string())),
                    ("product".into(), cpe.product().value()),
                    ("major".into(), cpe.version().value().map(to_major)),
                    ("version".into(), cpe.version().value()),
                ]
            }))),
            Box::new(Label(Package(|pkg| {
                vec![
                    ("name".into(), Some(pkg.package_name.clone())),
                    ("release".into(), pkg.package_version.clone()),
                ]
            }))),
            Box::new(Modify(|doc| {
                match (
                    doc.labels.get("major"),
                    doc.labels.get("version"),
                    doc.labels.get("release"),
                ) {
                    (Some(major), Some(version), Some(release)) if major == version => {
                        doc.labels
                            .insert("version".to_string(), major_minor(release));
                    }
                    _ => {}
                }
            })),
        ],
        ..Collector::default()
    };
    let collector = Arc::new(Mutex::new(collector));

    entries
        .par_iter()
        .progress_with(pb.clone())
        .try_for_each(|entry| {
            let data = Bytes::from(fs::read(entry)?);
            let mut data: BytesMut = Detector::default()
                .decompress(data)
                .map_err(|err| anyhow!("Decompression failed: {err}"))?
                .into();
            let sbom: SPDX = simd_json::from_slice(&mut data)?;

            pb.println(format!("{}", entry.display()));

            collector.lock().process(entry, &sbom)?;
            Ok::<_, anyhow::Error>(())
        })?;

    collector.lock().dump(&mut stdout().lock())?;

    if let Some(path) = cli.output {
        collector.lock().dump(&mut File::create(path)?)?;
    }

    Ok(())
}

#[derive(Copy, Clone)]
struct Context<'a> {
    pub id: &'a str,
    pub path: &'a Path,
    pub cpes: &'a [Uri<'a>],
    pub describing: &'a [&'a PackageInformation],
    pub sbom: &'a SPDX,
}

trait Extractor: Send {
    fn extract(&self, context: Context, document: &mut Document);
}

impl<F> Extractor for F
where
    F: for<'b> Fn(Context, &'b mut Document) + Send,
{
    fn extract(&self, context: Context, document: &mut Document) {
        self(context, document)
    }
}

struct Modify<F>(pub F)
where
    F: for<'a> Fn(&'a mut Document) + Send;

impl<F> Extractor for Modify<F>
where
    F: for<'a> Fn(&'a mut Document) + Send,
{
    fn extract(&self, _context: Context, document: &mut Document) {
        self.0(document)
    }
}

struct Cpe<F>(pub F)
where
    F: for<'a> Fn(&'a Uri<'a>) -> Vec<(String, Option<String>)> + Send;

struct Package<F>(pub F)
where
    F: for<'a> Fn(&'a PackageInformation) -> Vec<(String, Option<String>)> + Send;

trait LabelExtractor: Send {
    fn extract_label(&self, context: Context) -> Vec<(String, Option<String>)>;
}

impl<F> LabelExtractor for F
where
    F: Fn(Context) -> Vec<(String, Option<String>)> + Send,
{
    fn extract_label(&self, context: Context) -> Vec<(String, Option<String>)> {
        self(context)
    }
}

impl<F> LabelExtractor for Cpe<F>
where
    F: for<'a> Fn(&'a Uri<'a>) -> Vec<(String, Option<String>)> + Send,
{
    fn extract_label(&self, context: Context) -> Vec<(String, Option<String>)> {
        let mut result = Vec::new();
        for cpe in context.cpes {
            result.extend(self.0(cpe))
        }
        result
    }
}

impl<F> LabelExtractor for Package<F>
where
    F: for<'a> Fn(&'a PackageInformation) -> Vec<(String, Option<String>)> + Send,
{
    fn extract_label(&self, context: Context) -> Vec<(String, Option<String>)> {
        let mut result = Vec::new();
        for package in context.describing {
            result.extend(self.0(package))
        }
        result
    }
}

struct Label<F>(pub F)
where
    F: LabelExtractor;

impl<F: LabelExtractor> Extractor for Label<F> {
    fn extract(&self, context: Context, document: &mut Document) {
        let mut seen: HashMap<String, usize> = HashMap::new();

        for (mut key, value) in self.0.extract_label(context) {
            if let Some(value) = value.and_then(empty_to_none) {
                let count = seen.entry(key.clone()).or_insert(0);

                if *count > 0 {
                    // append suffix for duplicates
                    key = format!("{}_{}", key, *count);
                }

                *count += 1;

                document.labels.insert(key, value);
            }
        }
    }
}

#[derive(Default)]
struct Collector {
    pub extractors: Vec<Box<dyn Extractor>>,
    pub data: Data,
}

#[derive(Default)]
struct Data {
    pub files: usize,
    pub documents: BTreeMap<String, Document>,
}

#[derive(Default)]
struct Document {
    pub labels: BTreeMap<String, String>,
}

impl Collector {
    pub fn process(&mut self, path: &Path, sbom: &SPDX) -> anyhow::Result<()> {
        self.data.files += 1;

        let cpes = find_cpes(sbom);
        let cpes = cpes
            .iter()
            .map(|cpe| Uri::parse(cpe))
            .collect::<Result<Vec<_>, _>>()?;

        let describing = find_describing(sbom);

        let id = format!(
            "{}#{}",
            sbom.document_creation_information.spdx_document_namespace,
            path.file_name()
                .unwrap_or(path.as_os_str())
                .to_string_lossy()
        );

        let context = Context {
            id: &id,
            path,
            cpes: &cpes,
            describing: &describing,
            sbom,
        };

        let mut document = Document::default();
        for extractor in &self.extractors {
            extractor.extract(context, &mut document);
        }
        self.data.documents.insert(id, document);

        Ok(())
    }

    pub fn dump(&self, out: &mut impl std::io::Write) -> std::io::Result<()> {
        for (id, doc) in &self.data.documents {
            writeln!(out, "{id}")?;
            for (key, value) in &doc.labels {
                writeln!(out, "\t{key} = {value}")?;
            }
        }

        let groups = &["product", "major", "version", "release"];
        dump_grouped(out, groups, &self.data.documents)?;

        writeln!(out, "{} files", self.data.files)?;
        writeln!(out, "{} documents", self.data.documents.len())?;

        Ok(())
    }
}

fn find_cpes(spdx: &SPDX) -> Vec<String> {
    // extract CPEs
    find_describing(spdx)
        .into_iter()
        .flat_map(|pi| {
            pi.external_reference.iter().flat_map(|er| {
                if er.reference_type == "cpe22Type" {
                    Some(er.reference_locator.to_string())
                } else {
                    None
                }
            })
        })
        .collect()
}

fn find_describing(spdx: &SPDX) -> Vec<&PackageInformation> {
    // describes IDs
    let mut describes: HashSet<&str> = HashSet::from_iter(
        spdx.document_creation_information
            .document_describes
            .iter()
            .map(|s| s.as_str()),
    );

    // describes relationships
    for rel in &spdx.relationships {
        match rel.relationship_type {
            RelationshipType::Describes => {
                describes.insert(&rel.related_spdx_element);
            }
            RelationshipType::DescribedBy => {
                describes.insert(&rel.spdx_element_id);
            }
            _ => {}
        }
    }

    // collect packages

    let mut result = vec![];

    for package in &spdx.package_information {
        if describes.contains(package.package_spdx_identifier.as_str()) {
            result.push(package);
        }
    }

    result
}

pub trait ComponentValue {
    fn value(&self) -> Option<String>;
}

impl ComponentValue for Component<'_> {
    fn value(&self) -> Option<String> {
        match self {
            Self::Value(value) => Some(value.to_string()),
            _ => None,
        }
    }
}

fn dump_grouped(
    out: &mut impl std::io::Write,
    groups: &[&str],
    documents: &BTreeMap<String, Document>,
) -> std::io::Result<()> {
    fn recurse(
        out: &mut impl std::io::Write,
        groups: &[&str],
        docs: &[(String, &Document)],
        depth: usize,
    ) -> std::io::Result<()> {
        if groups.is_empty() {
            // leaf level: just print the document ids
            for (id, _) in docs {
                writeln!(out, "{:indent$}- {}", "", id, indent = depth * 2)?;
            }
            return Ok(());
        }

        let group_key = groups[0];

        // partition docs by the current group label
        let mut grouped: BTreeMap<&str, Vec<(String, &Document)>> = BTreeMap::new();
        for (id, doc) in docs {
            if let Some(val) = doc.labels.get(group_key) {
                grouped
                    .entry(val.as_str())
                    .or_default()
                    .push((id.clone(), doc));
            } else {
                grouped.entry("<none>").or_default().push((id.clone(), doc));
            }
        }

        // output each group
        for (val, subdocs) in grouped {
            writeln!(
                out,
                "{:indent$}{}: {}",
                "",
                group_key,
                val,
                indent = depth * 2
            )?;
            recurse(out, &groups[1..], &subdocs, depth + 1)?;
        }

        Ok(())
    }

    let docs: Vec<_> = documents.iter().map(|(id, d)| (id.clone(), d)).collect();
    recurse(out, groups, &docs, 0)
}

fn to_major(version: String) -> String {
    version
        .split_once('.')
        .map(|(major, _)| major.to_string())
        .unwrap_or(version)
}

fn empty_to_none(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}

fn major_minor(version: &str) -> String {
    version.splitn(3, '.').take(2).collect::<Vec<_>>().join(".")
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn major_minor_simple() {
        assert_eq!("1.2", major_minor("1.2.3"));
        assert_eq!("1.2", major_minor("1.2"));
        assert_eq!("1", major_minor("1"));
    }
}
