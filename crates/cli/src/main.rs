//! `psm`: command-line front end for the ps-manager password derivation.

#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a command-line tool reports through stdout and stderr"
)]

use std::io::{self, BufRead, IsTerminal};
use std::process::ExitCode;

use clap::builder::{PossibleValue, PossibleValuesParser, TypedValueParser};
use clap::{Args, Parser, Subcommand};
use psm_core::Zeroizing;
use psm_core::v1::{self, Policy, Profile, Request, RootKey, normalize};

const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (ps-manager/v1)");

/// Stateless password generator: the same inputs give the same password on
/// every device.
#[derive(Parser)]
#[command(
    name = "psm",
    version = VERSION,
    after_help = "Nothing is stored and nothing is sent anywhere. The password goes to stdout, \
                  everything else to stderr."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Derive the password for a site
    #[command(visible_alias = "g")]
    Generate {
        #[command(flatten)]
        request: RequestArgs,
        #[command(flatten)]
        key: KeyArgs,
    },
    /// Show only the master-key fingerprint
    Fingerprint {
        #[command(flatten)]
        key: KeyArgs,
    },
    /// Show how the inputs are normalized, without asking for the secret
    Normalize {
        #[command(flatten)]
        request: RequestArgs,
        /// Your identity, e.g. full name
        #[arg(short, long, env = "PSM_IDENTITY")]
        identity: Option<String>,
    },
    /// List password profiles
    Policies,
    /// Check this build against built-in test vectors
    Selftest,
}

#[derive(Args)]
struct RequestArgs {
    /// Website or service, e.g. github.com; URLs are accepted
    site: String,
    /// Account on the site, e.g. a login name, if you have more than one
    #[arg(short, long)]
    account: Option<String>,
    /// Rotation counter; increment it to change this one password
    #[arg(
        short,
        long,
        default_value_t = 1,
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    generation: u32,
    /// Password profile
    #[arg(short, long, default_value = "standard", value_parser = profile_parser())]
    profile: Profile,
    /// Password length [default: depends on the profile]
    #[arg(short, long)]
    length: Option<u32>,
}

impl RequestArgs {
    /// Validates everything up front, so a bad flag never costs a secret prompt.
    fn request(&self) -> Result<Request<'_>, String> {
        if normalize::site(&self.site).is_empty() {
            return Err(format!("site {:?} is empty after normalization", self.site));
        }
        let policy = Policy::new(self.profile, self.length).map_err(|e| e.to_string())?;
        Ok(Request {
            site: &self.site,
            account: self.account.as_deref().unwrap_or(""),
            generation: self.generation,
            policy,
        })
    }
}

#[derive(Args)]
struct KeyArgs {
    /// Your identity, e.g. full name [default: asked for]
    #[arg(short, long, env = "PSM_IDENTITY")]
    identity: Option<String>,
    /// Read the master secret from the first line of stdin instead of asking
    #[arg(long)]
    secret_stdin: bool,
}

impl KeyArgs {
    fn identity(&self) -> Result<String, String> {
        if let Some(identity) = &self.identity {
            return Ok(identity.clone());
        }
        if self.secret_stdin || !io::stdin().is_terminal() {
            return Err("no identity: pass --identity or set PSM_IDENTITY".into());
        }
        eprint!("Identity: ");
        let mut line = String::new();
        io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        Ok(line)
    }

    fn secret(&self) -> Result<Zeroizing<String>, String> {
        let mut secret = if self.secret_stdin {
            let mut line = Zeroizing::new(String::new());
            io::stdin()
                .lock()
                .read_line(&mut line)
                .map_err(|e| format!("reading master secret: {e}"))?;
            line
        } else {
            Zeroizing::new(
                rpassword::prompt_password("Master secret: ")
                    .map_err(|e| format!("reading master secret: {e}"))?,
            )
        };
        // Only the line terminator is removed; other white space is part of the secret.
        let len = secret.trim_end_matches(['\n', '\r']).len();
        secret.truncate(len);
        Ok(secret)
    }

    fn root_key(&self) -> Result<RootKey, String> {
        let identity = self.identity()?;
        let secret = self.secret()?;
        let key = RootKey::derive(&identity, &secret).map_err(|e| e.to_string())?;
        eprintln!("  identity     {}", normalize::text(&identity));
        eprintln!("  fingerprint  {}", key.fingerprint());
        Ok(key)
    }
}

/// Accepts the profile names of the spec and lists them, with descriptions,
/// in `--help`.
fn profile_parser() -> impl TypedValueParser<Value = Profile> {
    PossibleValuesParser::new(
        Profile::ALL.map(|p| PossibleValue::new(p.name()).help(p.description())),
    )
    .try_map(|name| Profile::from_name(&name))
}

fn describe(request: &Request) {
    let account = normalize::text(request.account);
    eprintln!("  site         {}", normalize::site(request.site));
    eprintln!(
        "  account      {}",
        if account.is_empty() {
            "(none)"
        } else {
            &account
        }
    );
    eprintln!("  generation   {}", request.generation);
    eprintln!(
        "  profile      {}, {} characters",
        request.policy.profile(),
        request.policy.length()
    );
}

fn generate(request: &RequestArgs, key: &KeyArgs) -> Result<(), String> {
    let request = request.request()?;
    let key = key.root_key()?;
    describe(&request);
    let password = key.password(&request).map_err(|e| e.to_string())?;
    println!("{}", password.as_str());
    Ok(())
}

fn show_normalized(request: &RequestArgs, identity: Option<&str>) -> Result<(), String> {
    if let Some(identity) = identity {
        eprintln!("  identity     {}", normalize::text(identity));
    }
    describe(&request.request()?);
    Ok(())
}

fn policies() {
    for p in Profile::ALL {
        let range = p.length_range();
        println!(
            "{:<13} {:>2} ({}-{})  {}",
            p.name(),
            p.default_length(),
            range.start(),
            range.end(),
            p.description()
        );
    }
}

fn selftest() -> Result<(), String> {
    eprintln!("Checking {} against built-in test vectors...", v1::ID);
    let checked = v1::selftest().map_err(|e| format!("SELF-TEST FAILED: {e}"))?;
    println!("ok: {checked} passwords match");
    Ok(())
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Generate { request, key } => generate(&request, &key),
        Command::Fingerprint { key } => key.root_key().map(drop),
        Command::Normalize { request, identity } => show_normalized(&request, identity.as_deref()),
        Command::Policies => {
            policies();
            Ok(())
        }
        Command::Selftest => selftest(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("psm: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn cli_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn version_names_the_algorithm() {
        assert!(VERSION.ends_with(&format!("({})", v1::ID)));
    }
}
