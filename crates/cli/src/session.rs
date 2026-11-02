//! `psm session`: derive the root key once, then generate passwords for as
//! many sites as needed.

use std::io::{self, BufRead};

use clap::Parser;
use psm_core::v1::RootKey;

use crate::clipboard::Clipboard;
use crate::{KeyArgs, OutputArgs, RequestArgs, describe};

const INTRO: &str = "Type a site and options as for `psm generate`, e.g. `github.com -a alice -g \
                     2`; -c copies the password. `help` lists the options; `exit` or Ctrl+D ends \
                     the session.";

/// Generate a password, with the options of `psm generate`
#[derive(Parser)]
#[command(name = "psm>", no_binary_name = true, disable_version_flag = true)]
struct Line {
    #[command(flatten)]
    request: RequestArgs,
    /// Copy this password to the clipboard instead of printing it
    #[arg(short, long)]
    clip: bool,
}

struct Session<'a> {
    root: RootKey,
    output: &'a OutputArgs,
    clipboard: Option<Clipboard>,
}

pub fn run(key: &KeyArgs, output: &OutputArgs) -> Result<(), String> {
    let mut session = Session {
        root: key.root_key()?,
        output,
        clipboard: None,
    };
    eprintln!("{INTRO}");
    let stdin = io::stdin();
    let mut line = String::new();
    loop {
        eprint!("psm> ");
        line.clear();
        if stdin
            .lock()
            .read_line(&mut line)
            .map_err(|e| e.to_string())?
            == 0
        {
            eprintln!();
            break;
        }
        let result = match line.trim() {
            "" => Ok(()),
            "exit" | "quit" => break,
            "help" => session.generate("--help"),
            input => session.generate(input),
        };
        if let Err(e) = result {
            eprintln!("{}", e.trim_end());
        }
    }
    if let Some(clipboard) = &session.clipboard {
        clipboard.clear();
    }
    Ok(())
}

impl Session<'_> {
    /// Errors come back ready to print, in clap's `error: ...` style.
    fn generate(&mut self, input: &str) -> Result<(), String> {
        let args = shlex::split(input).ok_or("error: unbalanced quotes")?;
        let line = Line::try_parse_from(args).map_err(|e| e.to_string())?;
        let request = line.request.request().map_err(|e| format!("error: {e}"))?;
        describe(&request);
        let password = self
            .root
            .password(&request)
            .map_err(|e| format!("error: {e}"))?;
        if !(self.output.clip || line.clip) {
            println!("{}", password.as_str());
            return Ok(());
        }
        let clipboard = match &mut self.clipboard {
            Some(clipboard) => clipboard,
            empty => empty.insert(
                Clipboard::new(self.output.clear_after()).map_err(|e| format!("error: {e}"))?,
            ),
        };
        clipboard
            .copy(&password)
            .map_err(|e| format!("error: {e}"))?;
        eprintln!(
            "  copied       cleared in {} s",
            clipboard.clear_after().as_secs()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn line_is_well_formed() {
        Line::command().debug_assert();
    }

    #[test]
    fn line_accepts_generate_options() {
        let args = shlex::split("'My Bank' -a alice -g 2 -p legacy -l 12 -c").unwrap();
        let line = Line::try_parse_from(args).unwrap();
        assert_eq!(line.request.site, "My Bank");
        assert_eq!(line.request.account.as_deref(), Some("alice"));
        assert_eq!(line.request.generation, 2);
        assert!(line.clip);
    }
}
