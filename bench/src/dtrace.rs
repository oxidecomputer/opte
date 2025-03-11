// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Tools for parsing lquantize histograms into `criterion`.

use super::MeasurementInfo;
use criterion::measurement::Measurement;
use criterion::measurement::ValueFormatter;
use criterion::measurement::WallTime;
use rand::distr::weighted::WeightedIndex;
use rand::prelude::*;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

pub struct DTraceHisto {
    pub label: Option<String>,
    pub bucket_width: u64,
    pub buckets: Vec<(u64, u64)>,
    pub rng_idx: OnceLock<WeightedIndex<u64>>,
}

impl DTraceHisto {
    pub fn from_path(
        path: impl AsRef<Path>,
        bucket_width: u64,
    ) -> anyhow::Result<Vec<Self>> {
        let data = std::fs::read_to_string(path)?;

        Self::from_str(&data, bucket_width)
    }

    pub fn from_str(
        data: &str,
        bucket_width: u64,
    ) -> anyhow::Result<Vec<Self>> {
        let mut out = vec![];
        let mut current_state = ParseState::NotBuilding;

        for line in data.lines() {
            let is_header = line.contains("value")
                && line.contains(" Distribution ")
                && line.contains("count");

            current_state = if is_header {
                current_state.header(bucket_width)?
            } else if line.is_empty() {
                let (state, histo) = current_state.blank_line()?;
                if let Some(histo) = histo {
                    out.push(histo);
                }
                state
            } else {
                current_state.data_line(line, bucket_width)?
            };
        }

        if let ParseState::Progress(p) = current_state {
            out.push(p)
        }

        Ok(out)
    }
}

enum ParseState {
    NotBuilding,
    FoundName(String),
    Progress(DTraceHisto),
}

impl ParseState {
    fn blank_line(self) -> anyhow::Result<(ParseState, Option<DTraceHisto>)> {
        Ok(match self {
            Self::NotBuilding => (Self::NotBuilding, None),
            Self::FoundName(n) => {
                anyhow::bail!("Expected header for histo {n}")
            }
            Self::Progress(histo) => (Self::NotBuilding, Some(histo)),
        })
    }

    fn header(self, bucket_width: u64) -> anyhow::Result<ParseState> {
        Ok(match self {
            Self::NotBuilding => Self::Progress(DTraceHisto {
                label: None,
                bucket_width,
                buckets: vec![],
                rng_idx: OnceLock::new(),
            }),
            Self::FoundName(label) => Self::Progress(DTraceHisto {
                label: Some(label),
                bucket_width,
                buckets: vec![],
                rng_idx: OnceLock::new(),
            }),
            Self::Progress(histo) => anyhow::bail!(
                "Unexpected header in {:?}: should finalise with blank line!",
                histo.label,
            ),
        })
    }

    fn data_line(
        self,
        line: &str,
        bucket_width: u64,
    ) -> anyhow::Result<ParseState> {
        let trimmed = line.trim();
        Ok(match self {
            Self::NotBuilding => Self::FoundName(trimmed.to_string()),
            Self::FoundName(label) => anyhow::bail!(
                "Unexpected extra name for {label}: wanted header."
            ),
            Self::Progress(mut histo) => {
                let mut divided = trimmed.split_whitespace();
                let mut time_slice = divided
                    .next()
                    .ok_or(anyhow::anyhow!("Failed to get first count."))?;

                // special case first and last buckets.
                let underlier = time_slice.contains('<');
                let overlier = time_slice.contains('>');
                if underlier || overlier {
                    time_slice = divided
                        .next()
                        .ok_or(anyhow::anyhow!("Failed to get first count."))?;
                }
                let count_slice = divided
                    .last()
                    .ok_or(anyhow::anyhow!("Failed to get first count."))?;

                // >= case naturally Just Works.
                let mut time = time_slice.parse::<u64>()?;
                if underlier {
                    time = time.saturating_sub(bucket_width);
                }

                histo.buckets.push((time, count_slice.parse()?));

                Self::Progress(histo)
            }
        })
    }
}

impl Measurement for DTraceHisto {
    type Intermediate = ();
    type Value = Duration;

    fn start(&self) -> Self::Intermediate {}

    // We use our parsed histogram as a PDF to draw new timing samples
    // from. We build up the WeightedIndex once it is needed, at which
    // point it will effectively mirror the input distribution.
    fn end(&self, _i: Self::Intermediate) -> Self::Value {
        let mut rng = rand::rng();
        let idx = self.rng_idx.get_or_init(|| {
            WeightedIndex::new(self.buckets.iter().map(|x| x.1)).unwrap()
        });

        let chosen_bucket = idx.sample(&mut rng);
        let sample = self.buckets[chosen_bucket].0;
        Duration::from_nanos(sample)
    }

    fn add(&self, v1: &Self::Value, v2: &Self::Value) -> Self::Value {
        *v1 + *v2
    }

    fn zero(&self) -> Self::Value {
        Duration::from_secs(0)
    }

    fn to_f64(&self, value: &Self::Value) -> f64 {
        value.as_nanos() as f64
    }

    fn formatter(&self) -> &dyn ValueFormatter {
        WallTime::formatter(&WallTime)
    }
}

impl MeasurementInfo for DTraceHisto {
    fn label() -> &'static str {
        "wallclock"
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_histogram() {
        let dtraces =
            DTraceHisto::from_str(include_str!("test/histos.out"), 256)
                .unwrap();

        assert_eq!(dtraces.len(), 2);
        assert_eq!(dtraces[0].label, Some("rx".to_string()));
        assert_eq!(dtraces[1].label, Some("tx".to_string()));

        assert!(dtraces[0].buckets.contains(&(7936, 2502)));
        assert!(dtraces[1].buckets.contains(&(3072, 969532)));
    }
}
