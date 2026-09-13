use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

pub fn print_banner() {
    let banner = r#"
  -  - - -   -   -
  -   - -
  - - -   -
  - - -   -
  - -  - - -
  -  -  - - -     -"#;
    println!("{}", banner.bright_cyan().bold());
    println!("{}", "  -".dimmed());
    println!(
        "  {}  {}  {}",
        "- SXIAUM Mainnet".bright_magenta().bold(),
        "-".dimmed(),
        "Chain ID: 13689".bright_yellow()
    );
    println!(
        "  {}  {}  {}",
        "- Native Token: SXI".bright_green().bold(),
        "-".dimmed(),
        "1 SXI = 1,000,000,000,000,000,000 aSXI".dimmed()
    );
    println!("{}", "  -".dimmed());
    println!();
}

pub fn print_success(msg: &str) {
    println!("{} {}", "-".green(), msg.bright_green());
}

pub fn print_error(msg: &str) {
    eprintln!("{} {}", "-".red(), msg.bright_red());
}

pub fn print_warning(msg: &str) {
    println!("{} {}", "- ".bright_yellow(), msg.yellow());
}

pub fn print_info(msg: &str) {
    println!("{} {}", "- ".bright_blue(), msg);
}

#[allow(dead_code)]
pub fn print_section(title: &str) {
    println!();
    println!("{}", format!("  - {} -", title).bright_cyan().bold());
}

pub fn create_spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(80));
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&["-", "-", "-", "-", "-", "-", "-", "-", "-", "-"])
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.set_message(msg.to_string());
    pb
}
