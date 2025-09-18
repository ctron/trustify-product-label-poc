# Trustify Product Labels PoC

This is PoC using labels for grouping SBOMs into a custom product hierarchy.

## Context

The idea is to convert a stream of SBOMs into a custom product hierarchy, by using labels and a profile configuration.
The labels should be extracted from SBOMs during the ingestion process.

## Running

> [!NOTE]
> In order to run this, you need Rust installed and cloned this repository.

### Preparation

Get tools:

```bash
cargo install sbom-cli
```

Or, if you have `cargo-binstall`:

```bash
cargo binstall sbom-cli
```

Then fetch all SBOM data from Red Hat:

```bash
sbom sync https://security.access.redhat.com/data/sbom/beta/ --key https://security.access.redhat.com/data/97f5eac4.txt#77E79ABE93673533ED09EBE2DCE3823597F5EAC4 -d sboms
```

### Playing

```bash
cargo run -- ./sboms --output output.txt
```

This will process all SBOMs and create two representations:

* All SBOMs and their discovered labels
* A product hierarchy using: `product`, `major`, `version`, `release`

## Example

An example output can be found here: [output.txt](output.txt)
