use derive_more::From;
use serde::Deserialize;
use std::collections::HashSet;
use std::error::Error as StdError;
use std::io::Read;
use std::ops::Deref;
use thiserror::Error as ThisError;
use url::{Origin, ParseError, Url};

#[derive(Deserialize, Debug)]
struct Test {
    id: u16,
    base: String,
    redirect_urls: Vec<String>,
    origins: Vec<String>,
    tests: Vec<String>,
}

#[derive(Debug)]
struct RedirectGuard<'a> {
    base_url: &'a Url,
    redirect_urls: &'a HashSet<Url>,
    origins: &'a HashSet<Origin>,
}

impl<'a> RedirectGuard<'a> {
    fn validate(&self, input: &str) -> Result<Validated, Error> {
        let input = self.base_url.join(input)?;
        if self.base_url.origin() == input.origin() {
            return Ok(Validated(input));
        }

        if self.redirect_urls.contains(&input) {
            return Ok(Validated(input));
        }

        if self
            .origins
            .into_iter()
            .chain(std::iter::once(&self.base_url.origin()))
            .any(|o| o == &input.origin())
        {
            return Ok(Validated(input));
        }

        Err(Error::ForbiddenRedirect(input))
    }
}

pub struct Validated(Url);

impl Deref for Validated {
    type Target = Url;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(ThisError, Debug, From)]
pub enum Error {
    #[error("invalid URL {0}")]
    InvalidUrl(ParseError),
    #[error("forbidden redirect {0}")]
    ForbiddenRedirect(Url),
}

fn load_tests(path: &str) -> Result<Vec<Test>, Box<dyn StdError>> {
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![];
    f.read_to_end(&mut buf)?;
    serde_json::from_slice(&buf).map_err(|e| e.into())
}

fn main() -> Result<(), Box<dyn StdError>> {
    let config = load_tests("config.json")?;

    for c in config {
        let base_url = c.base.parse()?;
        let redirect_urls = c
            .redirect_urls
            .iter()
            .map(String::as_str)
            .map(Url::parse)
            .collect::<Result<_, _>>()?;
        let origins = c
            .origins
            .iter()
            .map(String::as_str)
            .map(|s| match s.parse::<Url>() {
                Ok(url) => Ok(url.origin()),
                Err(e) => Err(e),
            })
            .collect::<Result<_, _>>()?;

        let guard = RedirectGuard {
            base_url: &base_url,
            redirect_urls: &redirect_urls,
            origins: &origins,
        };

        println!("==== test {} ============", c.id);
        println!("base:\n{}\n", c.base);

        let mut valid = vec![];
        let mut invalid = vec![];

        for t in c.tests {
            match guard.validate(&t) {
                Ok(v) => valid.push((&*v).clone()),
                Err(v) => invalid.push((t, v)),
            }
        }

        println!("valid redirects:");
        for v in valid {
            println!("{v}");
        }
        println!("\ninvalid redirects:");
        for v in invalid {
            println!("{} -> {}", v.0, v.1);
        }

        println!("========================")
    }

    Ok(())
}
