// Copyright 2019 Glenn Mohre, Sonatype.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use cargo_pants::filter_vulnerabilities;
use cargo_pants::ParseCargoToml;
use cargo_pants::ParseToml;
use cargo_pants::{client::OSSIndexClient, coordinate::Coordinate};
use console::style;
use console::StyledObject;
use structopt::StructOpt;
use tracing::info;

use std::io::{stdout, Write};
use std::path::PathBuf;
use std::{env, io, process};

#[path = "../../common.rs"]
mod common;

mod cli;

fn main() {
    let opt = cli::Opt::from_args();

    match opt {
        cli::Opt::Pants {
            toml_file,
            log_level,
            include_dev_dependencies,
            loud,
            no_color,
            pants_style,
            oss_index_api_key,
            ignore_file,
        } => {
            common::construct_logger(".ossindex", log_level);

            if let Some(pants_style) = pants_style {
                check_pants(&pants_style);
            }

            common::print_dev_dependencies_info(include_dev_dependencies);

            if let Err(e) = audit(
                toml_file.to_string_lossy().to_string(),
                oss_index_api_key,
                loud,
                !no_color,
                include_dev_dependencies,
                ignore_file,
            ) {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
        }
    }
}

fn audit(
    toml_file_path: String,
    oss_index_api_key: Option<String>,
    verbose_output: bool,
    enable_color: bool,
    include_dev: bool,
    ignore_file: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut parser = ParseCargoToml::new(toml_file_path.clone(), include_dev);
    let packages = parser.get_packages()?;

    let api_key = oss_index_api_key.unwrap_or_else(|| {
        info!("Warning: missing optional 'OSS_INDEX_API_KEY'");
        String::new()
    });

    let client = OSSIndexClient::new(api_key);
    let coordinates: Vec<Coordinate> = packages
        .chunks(128)
        .flat_map(|chunk| client.post_coordinates(chunk.to_vec()))
        .collect();

    // Ignore vulns
    let mut filtered_coordinates = coordinates.clone();
    filter_vulnerabilities(&mut filtered_coordinates, ignore_file);

    let (vulnerable_package_count, non_vulnerable_package_count) = filtered_coordinates
        .iter()
        .fold((0, 0), |(vuln, non_vuln), coord| {
            if coord.has_vulnerabilities() {
                (vuln + 1, non_vuln)
            } else {
                (vuln, non_vuln + 1)
            }
        });

    let mut stdout = stdout();
    if verbose_output {
        common::banner(
            env!("CARGO_BIN_NAME").to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
        );

        write_package_output(
            &mut stdout,
            &filtered_coordinates,
            non_vulnerable_package_count,
            false,
            enable_color,
            None,
            &parser,
        )?;
    } else if vulnerable_package_count > 0 {
        write_package_output(
            &mut stdout,
            &filtered_coordinates,
            vulnerable_package_count,
            true,
            enable_color,
            None,
            &parser,
        )?;
    }

    // show a summary so folks know we are not pantless
    println!("{}", get_summary_message(coordinates.len() as u32, vulnerable_package_count));

    if vulnerable_package_count == 0 {
        Ok(())
    } else {
        process::exit(3);
    }
}

fn write_package_output(
    output: &mut dyn Write,
    coordinates: &[Coordinate],
    package_count: u32,
    vulnerable: bool,
    enable_color: bool,
    width_override: Option<u16>,
    parser: &impl ParseToml,
) -> io::Result<()> {
    let vulnerability = if vulnerable {
        "Vulnerable"
    } else {
        "Non-vulnerable"
    };

    writeln!(output, "\n{} Dependencies\n", vulnerability)?;

    for (index, coordinate) in coordinates
        .iter()
        .filter(|c| vulnerable == c.has_vulnerabilities())
        .enumerate()
    {
        if enable_color {
            writeln!(
                output,
                "[{}/{}] {}",
                index + 1,
                package_count,
                style_purl(vulnerable, coordinate.purl.clone())
            )?;
        } else {
            writeln!(
                output,
                "[{}/{}] {}",
                index + 1,
                package_count,
                coordinate.purl
            )?;
        }
        if vulnerable {
            let vulnerability_count = coordinate.vulnerabilities.len();
            let plural_text = if vulnerability_count == 1 {
                "vulnerability"
            } else {
                "vulnerabilities"
            };

            let text = format!("{} known {} found", vulnerability_count, plural_text);
            if enable_color {
                writeln!(output, "{}", style(text).red())?;
            } else {
                writeln!(output, "{}", text)?;
            }

            for vulnerability in &coordinate.vulnerabilities {
                if !vulnerability.title.is_empty() {
                    vulnerability
                        .output_table(output, enable_color, width_override)
                        .expect("Unable to output Vulnerability details");
                    writeln!(output, "\n")?;
                }
            }

            println!("Inverse Dependency graph");
            parser.print_the_graph(coordinate.purl.clone())?;
            println!();
        }
    }
    Ok(())
}

fn style_purl(vulnerable: bool, purl: String) -> StyledObject<String> {
    if vulnerable {
        style(purl).red().bold()
    } else {
        style(purl).green()
    }
}

fn get_summary_message(component_count: u32, vulnerability_count: u32) -> String {
    format!(
        "\nAudited Dependencies: {}\nVulnerable Dependencies: {}\n",
        component_count, vulnerability_count
    )
}

fn check_pants(n: &str) -> ! {
    match n {
        "JNCO" => {
            println!("{}", "Amber is the color of your energy");
            process::exit(311)
        }
        "Wrangler" => {
            println!("{}", "The 80s are over, friend");
            process::exit(1982)
        }
        "Levi" => {
            println!("{}", "Yippie Ki Yay, friendo bendo");
            process::exit(12251987)
        }
        _ => {
            println!("{}", "Uhhhhh");
            process::exit(1337)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cargo_pants::parse::TestParseCargoToml;
    use cargo_pants::Vulnerability;

    fn setup_test_coordinates() -> (Vec<Coordinate>, u32) {
        let mut coordinates: Vec<Coordinate> = Vec::new();

        let mut coord1 = Coordinate::default();
        coord1.purl = "coord one purl-1vuln".to_owned();
        let mut coord1_vuln1 = Vulnerability::default();
        coord1_vuln1.title = "coord1-vuln1 title".to_owned();
        coord1.vulnerabilities.push(coord1_vuln1);
        coordinates.push(coord1);

        let mut coord2 = Coordinate::default();
        coord2.purl = "coord two purl-3vulns".to_owned();
        let mut coord2_vuln1 = Vulnerability::default();
        coord2_vuln1.title = "coord2-vuln1 title".to_owned();
        coord2.vulnerabilities.push(coord2_vuln1);

        // empty title for vuln_two is intentional
        coord2.vulnerabilities.push(Vulnerability::default());

        let mut coord2_vuln3 = Vulnerability::default();
        coord2_vuln3.title = "coord2-vuln3 title".to_owned();
        coord2.vulnerabilities.push(coord2_vuln3);
        coordinates.push(coord2);

        let mut coordinate_three = Coordinate::default();
        coordinate_three.purl = "coord three purl-no vulns".to_owned();
        coordinates.push(coordinate_three);

        let package_count = coordinates.len() as u32;
        (coordinates, package_count)
    }

    fn convert_output(output: &[u8]) -> &str {
        std::str::from_utf8(output).expect("Could not convert output to UTF-8")
    }

    #[test]
    fn write_package_output_non_vulnerable() {
        let parser = TestParseCargoToml::new("".to_string(), false);
        let (coordinates, package_count) = setup_test_coordinates();
        let mut package_output = Vec::new();
        write_package_output(
            &mut package_output,
            &coordinates,
            package_count,
            false,
            false,
            Some(30),
            &parser,
        )
        .expect("Failed to write package output");
        assert_eq!(
            convert_output(&package_output),
            "\nNon-vulnerable Dependencies\n\n[1/3] coord three purl-no vulns\n"
        );
    }

    #[test]
    fn write_package_output_vulnerable() {
        let parser = TestParseCargoToml::new("".to_string(), false);
        let (coordinates, package_count) = setup_test_coordinates();
        let mut package_output = Vec::new();
        write_package_output(
            &mut package_output,
            &coordinates,
            package_count,
            true,
            false,
            Some(30),
            &parser,
        )
        .expect("Failed to write package output");
        assert_eq!(
            convert_output(&package_output),
            "\nVulnerable Dependencies\n\n[1/3] coord one purl-1vuln\n1 known vulnerability found\n\nVulnerability Title: coord1-vuln1 title\n╭─────────────┬───╮\n│ ID          │   │\n├─────────────┼───┤\n│ Description │   │\n├─────────────┼───┤\n│ CVSS Score  │ 0 │\n├─────────────┼───┤\n│ CVSS Vector │   │\n├─────────────┼───┤\n│ Reference   │   │\n╰─────────────┴───╯\n\n\n[2/3] coord two purl-3vulns\n3 known vulnerabilities found\n\nVulnerability Title: coord2-vuln1 title\n╭─────────────┬───╮\n│ ID          │   │\n├─────────────┼───┤\n│ Description │   │\n├─────────────┼───┤\n│ CVSS Score  │ 0 │\n├─────────────┼───┤\n│ CVSS Vector │   │\n├─────────────┼───┤\n│ Reference   │   │\n╰─────────────┴───╯\n\n\n\nVulnerability Title: coord2-vuln3 title\n╭─────────────┬───╮\n│ ID          │   │\n├─────────────┼───┤\n│ Description │   │\n├─────────────┼───┤\n│ CVSS Score  │ 0 │\n├─────────────┼───┤\n│ CVSS Vector │   │\n├─────────────┼───┤\n│ Reference   │   │\n╰─────────────┴───╯\n\n\n"
        );
    }

    #[test]
    fn get_summary_message_content() {
        let summary_message = get_summary_message(2, 1);
        assert_eq!(
            summary_message,
            "\nAudited Dependencies: 2\nVulnerable Dependencies: 1\n"
        );
    }
}
