#[macro_use]
extern crate prometheus;
extern crate chrono;
extern crate pest;
#[macro_use]
extern crate pest_derive;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
extern crate clap;
extern crate ipnetwork;

use chrono::prelude::*;
use clap::{App, Arg};
use failure::Error;
use pest::Parser;
use std::convert::TryFrom;

use hyper::{rt::Future, service::service_fn_ok, Body, Response, Server};
use prometheus::{
    linear_buckets, Encoder, Gauge, Histogram, HistogramVec, IntGaugeVec, TextEncoder,
};

#[derive(Debug, PartialEq, Eq)]
pub enum BindingState {
    Active,
    Free,
    Abandoned,
    Unknown,
}

impl Default for BindingState {
    fn default() -> BindingState {
        BindingState::Unknown
    }
}

#[derive(Debug)]
pub struct Lease {
    pub ip: std::net::Ipv4Addr,
    pub hardware_ethernet: String,
    pub starts: DateTime<Utc>,
    pub ends: DateTime<Utc>,
    pub tstp: DateTime<Utc>,
    pub cltt: DateTime<Utc>,
    pub binding_state: BindingState,
    pub uid: String,
}

impl Default for Lease {
    fn default() -> Lease {
        let dt = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc);
        Lease {
            ip: std::net::Ipv4Addr::new(0, 0, 0, 0),
            hardware_ethernet: String::default(),
            starts: dt,
            ends: dt,
            tstp: dt,
            cltt: dt,
            binding_state: BindingState::default(),
            uid: String::default(),
        }
    }
}

#[derive(Debug, Fail)]
enum ParseError {
    #[fail(display = "datetime rule not found")]
    DateTimeNotFound,
    #[fail(display = "Missing one or more datetime fields")]
    None,

    #[fail(display = "Missing field {}", field)]
    FieldMissing { field: String },

    #[fail(display = "Unknown binding state: {}", value)]
    UnknownBindingState { value: String },
}

fn parse_datetime(pairs: pest::iterators::Pair<'_, Rule>) -> Result<DateTime<Utc>, Error> {
    match pairs.into_inner().find(|p| p.as_rule() == Rule::datetime) {
        Some(p) => {
            let mut inner = p.into_inner().skip(1).take(6); // skip the weekday
            let year = inner.next().ok_or(ParseError::None)?.as_str();
            let month = inner.next().ok_or(ParseError::None)?.as_str();
            let day = inner.next().ok_or(ParseError::None)?.as_str();
            let hour = inner.next().ok_or(ParseError::None)?.as_str();
            let minute = inner.next().ok_or(ParseError::None)?.as_str();
            let second = inner.next().ok_or(ParseError::None)?.as_str();

            Ok(Utc
                .ymd(year.parse()?, month.parse()?, day.parse()?)
                .and_hms(hour.parse()?, minute.parse()?, second.parse()?))
        }
        None => Err(ParseError::DateTimeNotFound.into()),
    }
}

fn parse_binding_state(p: pest::iterators::Pair<'_, Rule>) -> Result<BindingState, ParseError> {
    let value = p
        .into_inner()
        .find(|p| p.as_rule() == Rule::unquoted_value)
        .ok_or(ParseError::FieldMissing {
            field: String::from("unquoted_value"),
        })?;

    Ok(match value.as_str() {
        "active" => BindingState::Active,
        "free" => BindingState::Free,
        "abandoned" => BindingState::Abandoned,
        x => {
            return Err(ParseError::UnknownBindingState {
                value: x.to_string(),
            })
        }
    })
}
impl TryFrom<pest::iterators::Pair<'_, Rule>> for Lease {
    type Error = Error;
    fn try_from(pairs: pest::iterators::Pair<'_, Rule>) -> Result<Lease, Self::Error> {
        let mut lease = Lease::default();
        for pair in pairs.into_inner() {
            match pair.as_rule() {
                Rule::address => lease.ip = pair.as_str().parse()?,
                Rule::lease_fields => {
                    for field in pair.into_inner() {
                        match field.as_rule() {
                            Rule::starts_field => lease.starts = parse_datetime(field)?,
                            Rule::ends_field => lease.ends = parse_datetime(field)?,
                            Rule::tstp_field => lease.tstp = parse_datetime(field)?,
                            Rule::cltt_field => lease.cltt = parse_datetime(field)?,
                            Rule::binding_state_field => {
                                lease.binding_state = parse_binding_state(field)?
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(lease)
    }
}

#[derive(Parser, Debug)]
#[grammar = "lease.pest"]
struct LeaseParser;

lazy_static! {
    static ref PARSE_TIME: Histogram = register_histogram!(histogram_opts!(
        "dhcpd_parse_time",
        "Time it took to parse the lease file",
        linear_buckets(10.0, 15.0, 15).unwrap()
    ))
    .unwrap();
    static ref ACTIVE_LEASE_AGE: HistogramVec = register_histogram_vec!(
        "dhcpd_active_lease_age",
        "Age of active leases",
        &["network"],
        vec![60.0, 300.0, 600.0, 1200.0, 1500.0, 2100.0, 2400.0, 2700.0, 3600.0]
    )
    .unwrap();
    static ref LEASES: IntGaugeVec = register_int_gauge_vec!(
        "dhcpd_leases",
        "Total known DHCP leases",
        &["network", "binding_state", "valid"]
    )
    .unwrap();
}

fn read_leases(filename: &str) -> Result<Vec<Lease>, Error> {
    let inp = std::fs::read_to_string(filename)?;
    let pairs = LeaseParser::parse(Rule::lease_file, &inp).unwrap_or_else(|e| panic!("{}", e));
    Ok(pairs
        .filter(|p| p.as_rule() == Rule::lease)
        .map(Lease::try_from)
        .collect::<Result<Vec<_>, _>>()?)
}

fn update_counter(filename: &str, networks: &[ipnetwork::Ipv4Network]) -> Result<u128, Error> {
    use std::time::Instant;
    let now = Utc::now();

    let start = Instant::now();
    let leases = read_leases(filename)?;
    let end = Instant::now();
    let duration = (end - start).as_millis();

    PARSE_TIME.observe(duration as f64);

    let valid = |l: &&Lease| l.ends > now;
    let invalid = |l: &&Lease| l.ends <= now;
    let active = |l: &&Lease| l.binding_state == BindingState::Active;
    let free = |l: &&Lease| l.binding_state == BindingState::Free;
    let abandoned = |l: &&Lease| l.binding_state == BindingState::Abandoned;

    let filters: Vec<(&Fn(&&Lease) -> bool, &Fn(&&Lease) -> bool, &[&str])> = vec![
        (&active, &valid, &["active", "true"]),
        (&active, &invalid, &["active", "false"]),
        (&free, &valid, &["free", "true"]),
        (&free, &invalid, &["free", "false"]),
        (&abandoned, &valid, &["free", "true"]),
        (&abandoned, &invalid, &["free", "false"]),
    ];

    for (i, (f1, f2, filter_labels)) in filters.iter().enumerate() {
        for network in networks {
            let n = format!("{}", network);
            let labels = {
                let mut labels = vec![&n[..]];
                labels.extend(filter_labels.iter().cloned());
                labels
            };
            let leases: Vec<&Lease> = leases.iter().filter(|l| network.contains(l.ip)).collect();

            if i == 0 {
                // once for every network
                let histogram = ACTIVE_LEASE_AGE.with_label_values(&[&n]);
                for lease in leases.iter().cloned().filter(active).filter(valid) {
                    let age = ((now - lease.starts).num_milliseconds() as f64) / 1000.;
                    histogram.observe(age);
                }
            }

            let ls = leases.iter().cloned().filter(f1).filter(f2).count();
            LEASES.with_label_values(&labels[..]).set(ls as i64);
        }
    }

    Ok(duration)
}

fn is_subnet(net: String) -> Result<(), String> {
    match net.parse::<ipnetwork::Ipv4Network>() {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Invalid IPv4Network: {}", e)),
    }
}

fn is_file(file: String) -> Result<(), String> {
    let path = std::path::Path::new(&file);

    if !path.exists() {
        return Err(format!("File {} does not exist", file));
    } else if let Err(e) = std::fs::File::open(path) {
        return Err(format!("File {} is not readable: {}", file, e));
    }

    Ok(())
}

fn main() {
    let matches = App::new("dhcpd-exporter")
        .version("0.1")
        .author("Andreas Rammhold <andreas@rammhold.de>")
        .arg(
            Arg::with_name("PORT")
                .short("p")
                .long("port")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("LEASE_FILE")
                .required(true)
                .validator(is_file),
        )
        .arg(
            Arg::with_name("SUBNET")
                .required(true)
                .multiple(true)
                .validator(is_subnet),
        )
        .get_matches();

    let port = matches
        .value_of("PORT")
        .unwrap_or("9267")
        .parse()
        .expect("Not a valid port");

    let filename = matches
        .value_of("LEASE_FILE")
        .expect("lease file missing")
        .to_string();

    let raw_subnets = matches.values_of("SUBNET").expect("Subnets missing");
    let subnets: Vec<ipnetwork::Ipv4Network> = raw_subnets
        .map(|n| n.parse())
        .collect::<Result<_, _>>()
        .unwrap();

    let addr = ([0, 0, 0, 0, 0, 0, 0, 0], port).into();
    println!("Listening on {}", addr);

    std::thread::spawn(move || {
        let run = || {
            println!("Updating DHCPD leases metrics");
            match update_counter(&filename, &subnets) {
                Err(e) => println!("Failed to update metrics: {:?}", e),
                Ok(d) => println!("Update finished in {}ms", d),
            }
        };

        run();

        loop {
            use std::{thread::sleep, time::Duration};
            sleep(Duration::from_secs(15));
            run();
        }
    });
    let new_service = || {
        let encoder = TextEncoder::new();
        service_fn_ok(move |_request| {
            let metric_families = prometheus::gather();
            let mut buffer = vec![];
            encoder.encode(&metric_families, &mut buffer).unwrap();

            Response::builder()
                .status(200)
                .body(Body::from(buffer))
                .unwrap()
        })
    };

    let server = Server::bind(&addr)
        .serve(new_service)
        .map_err(|e| eprintln!("Server error: {}", e));

    hyper::rt::run(server);
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     #[test]
//     fn test_parse_quoted_value() {
//         let tests = vec![
//             ("\"foo\"", "foo"),
//             (r#""foo""#, "foo"),
//             (r#""foo\"""#, r#"foo\""#),
//             (r#""\000""#, r#"\000"#),
//             (r#""\\"a""#, r#"\\"a"#),
//             (r#""\""#, r#"\"#),
//             (
//                 r#""\001\024\302\023\332\211>""#,
//                 r#"\001\024\302\023\332\211>"#,
//             ),
//         ];
//
//         for (inp, outp) in tests.iter() {
//             match LeaseParser::parse(Rule::quoted_value, inp) {
//                 Ok(res) => {
//                     println!("{:?}", res);
//                     assert_eq!(res.as_str(), *outp);
//                 }
//                 Err(e) => {
//                     panic!("{}", e);
//                 }
//             }
//         }
//     }
// }
