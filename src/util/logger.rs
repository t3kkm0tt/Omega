use std::{
    collections::{BTreeMap, HashMap},
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    sync::{OnceLock, mpsc},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use ansi_term::Color;
use json::JsonValue;
use ttp_core::{CommunicationValue, DataTypes, DataValue};

static LOGGER: OnceLock<mpsc::Sender<LogMessage>> = OnceLock::new();

#[derive(Clone, Copy)]
#[allow(unused)]
pub enum PrintType {
    Call,
    Client,
    Iota,
    Omikron,
    Omega,
    General,
}

struct LogMessage {
    timestamp_ms: u128,
    sender: Option<i64>,
    prefix: &'static str,
    kind: PrintType,
    is_error: bool,
    message: String,
}

pub fn startup() {
    let (tx, rx) = mpsc::channel::<LogMessage>();
    LOGGER.set(tx).expect("Logger already initialized");

    thread::spawn(move || {
        let log_dir = Path::new("logs");
        fs::create_dir_all(log_dir).expect("Failed to create log directory");

        let start_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let path = log_dir.join(format!("log_{}.txt", start_ts));
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("Failed to open log file");

        for msg in rx {
            let ts = fixed_box(&msg.timestamp_ms.to_string(), 13);
            let sender = match msg.sender {
                Some(id) => fixed_box(&id.to_string(), 19),
                _ => fixed_box("", 19),
            };

            let line = format!("{} {} {} {}", ts, sender, msg.prefix, msg.message);

            println!("{}", colorize(msg.kind, msg.is_error).paint(&line));

            let _ = writeln!(file, "{}", line);
        }
    });
}

fn colorize(kind: PrintType, is_error: bool) -> Color {
    if is_error {
        return Color::Red;
    }

    match kind {
        PrintType::Call => Color::Purple,
        PrintType::Client => Color::Green,
        PrintType::Iota => Color::Yellow,
        PrintType::Omikron => Color::Blue,
        PrintType::Omega => Color::Cyan,
        PrintType::General => Color::White,
    }
}

fn fixed_box(content: &str, width: usize) -> String {
    let s: String = content.chars().take(width).collect();
    let len = s.chars().count();
    if len < width {
        format!("[{}{}]", " ".repeat(width - len), s)
    } else {
        s
    }
}

pub fn log_internal(
    sender: Option<i64>,
    kind: PrintType,
    prefix: &'static str,
    is_error: bool,
    message: String,
) {
    if let Some(tx) = LOGGER.get() {
        let _ = tx.send(LogMessage {
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            sender,
            prefix,
            kind,
            is_error,
            message,
        });
    }
}

#[macro_export]
macro_rules! log {
    // plain
    ($($arg:tt)*) => {
        $crate::util::logger::log_internal(
            None,
            $crate::util::logger::PrintType::General,
            "",
            false,
            format!($($arg)*)
        )
    };

    // sender + actor
    ($sender:expr, $kind:expr, $($arg:tt)*) => {
        $crate::util::logger::log_internal(Some($sender), $kind, "", false, format!($($arg)*))
    };

    // actor only
    ($kind:expr, $($arg:tt)*) => {
        $crate::util::logger::log_internal(None, $kind, "", false, format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_in {
    // sender + actor
    ($sender:expr, $kind:expr, $($arg:tt)*) => {
        $crate::util::logger::log_internal(Some($sender), $kind, ">", false, format!($($arg)*))
    };

    // actor only
    ($kind:expr, $($arg:tt)*) => {
        $crate::util::logger::log_internal(None, $kind, ">", false, format!($($arg)*))
    };

    // plain
    ($($arg:tt)*) => {
        $crate::util::logger::log_internal(
            None,
            $crate::util::logger::PrintType::General,
            ">",
            false,
            format!($($arg)*)
        )
    };
}

#[macro_export]
macro_rules! log_out {

    // sender + actor
    ($sender:expr, $kind:expr, $($arg:tt)*) => {
        $crate::util::logger::log_internal(Some($sender), $kind, "<", false, format!($($arg)*))
    };

    // actor only
    ($kind:expr, $($arg:tt)*) => {
        $crate::util::logger::log_internal(None, $kind, "<", false, format!($($arg)*))
    };

    // plain
    ($($arg:tt)*) => {
        $crate::util::logger::log_internal(
            None,
            $crate::util::logger::PrintType::General,
            "<",
            false,
            format!($($arg)*)
        )
    };
}

#[macro_export]
macro_rules! log_err {

    // sender + actor
    ($sender:expr, $kind:expr, $($arg:tt)*) => {
        $crate::util::logger::log_internal(Some($sender), $kind, ">>", true, format!($($arg)*))
    };

    // actor only
    ($kind:expr, $($arg:tt)*) => {
        $crate::util::logger::log_internal(None, $kind, ">>", true, format!($($arg)*))
    };

    // plain
    ($($arg:tt)*) => {
        $crate::util::logger::log_internal(
            None,
            $crate::util::logger::PrintType::General,
            ">>",
            true,
            format!($($arg)*)
        )
    };
}

// ******** COMMUNICATION VALUES ********
pub fn log_cv_internal(
    prefix: &'static str,
    cv: &CommunicationValue,
    print_type: Option<PrintType>,
) {
    let formatted = format_cv(cv);

    log_internal(
        Some(cv.get_sender() as i64),
        print_type.unwrap_or(PrintType::General),
        prefix,
        false,
        formatted,
    );
}

pub fn format_cv(cv: &CommunicationValue) -> String {
    let mut parts = Vec::new();

    let sender = cv.get_sender();
    let receiver = cv.get_receiver();

    if sender > 0 && receiver > 0 {
        parts.push(format!("{} > {}", sender, receiver));
    } else if sender > 0 {
        parts.push(format!("{}", sender));
    } else if receiver > 0 {
        parts.push(format!("> {}", receiver));
    }

    let comm_type = cv.get_type().to_string();
    parts.push(format!("{}", comm_type));

    let data: &BTreeMap<DataTypes, DataValue> = cv.get_data_container();

    let formated_data =
        format_data_container(data.iter().map(|(k, v)| (k.clone(), v.clone())).collect());

    parts.push(format!("{}", formated_data));

    parts.join(": ")
}

fn format_data_container(data: Vec<(DataTypes, DataValue)>) -> String {
    let parts: Vec<String> = data
        .into_iter()
        .map(|(key, value)| {
            let key_str = key.to_string();

            match value {
                DataValue::Str(s) => format!("{}=\"{}\"", key_str, s),

                DataValue::Container(inner) => {
                    let inner_formatted = format_data_container(inner);
                    format!("{}={{ {} }}", key_str, inner_formatted)
                }

                DataValue::Array(arr) => {
                    let arr_formatted = format_array(arr);
                    format!("{}=[{}]", key_str, arr_formatted)
                }

                DataValue::Bool(b) => format!("{}={}", key_str, b),

                DataValue::BoolTrue => format!("{}=true", key_str),
                DataValue::BoolFalse => format!("{}=false", key_str),

                DataValue::Number(num) => format!("{}={}", key_str, num),

                _ => "".to_string(),
            }
        })
        .collect();

    parts.join(", ")
}

fn format_array(arr: Vec<DataValue>) -> String {
    let parts: Vec<String> = arr
        .into_iter()
        .map(|value| match value {
            DataValue::Str(s) => format!("\"{}\"", s),

            DataValue::Container(inner) => {
                let inner_formatted = format_data_container(inner);
                format!("{{ {} }}", inner_formatted)
            }

            DataValue::Array(inner_arr) => {
                let formatted = format_array(inner_arr);
                format!("[{}]", formatted)
            }

            DataValue::Bool(b) => b.to_string(),

            DataValue::BoolTrue => "true".to_string(),
            DataValue::BoolFalse => "false".to_string(),

            DataValue::Number(num) => num.to_string(),

            _ => String::new(),
        })
        .collect();

    parts.join(", ")
}
#[macro_export]
macro_rules! log_cv {
    ($kind:expr, $cv:expr) => {
        $crate::util::logger::log_cv_internal("", &$cv, Some($kind))
    };
    ($cv:expr) => {
        $crate::util::logger::log_cv_internal("", &$cv, None)
    };
}

#[macro_export]
macro_rules! log_cv_in {
    ($kind:expr, $cv:expr) => {
        $crate::util::logger::log_cv_internal("> ", &$cv, Some($kind))
    };
    ($cv:expr) => {
        $crate::util::logger::log_cv_internal("> ", &$cv, None)
    };
}
#[macro_export]
macro_rules! log_cv_out {
    ($kind:expr, $cv:expr) => {
        $crate::util::logger::log_cv_internal("< ", &$cv, Some($kind))
    };
    ($cv:expr) => {
        $crate::util::logger::log_cv_internal("< ", &$cv, None)
    };
}
