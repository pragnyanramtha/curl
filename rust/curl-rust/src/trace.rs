use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::cli::{TraceConfig, TraceMode, TransferConfig};
use crate::error::Result;

const ASCII_WIDTH: usize = 0x40;
const BINARY_WIDTH: usize = 0x10;

#[derive(Clone, Copy)]
pub enum TraceEvent {
    SendHeader,
    SendData,
    RecvHeader,
    RecvData,
}

impl TraceEvent {
    fn label(self) -> &'static str {
        match self {
            Self::SendHeader => "=> Send header",
            Self::SendData => "=> Send data",
            Self::RecvHeader => "<= Recv header",
            Self::RecvData => "<= Recv data",
        }
    }
}

pub fn prepare_trace_outputs(transfers: &[TransferConfig]) -> Result<()> {
    let mut prepared = HashSet::new();
    for transfer in transfers {
        let Some(trace) = &transfer.trace else {
            continue;
        };
        if is_standard_stream(&trace.target) || !prepared.insert(trace.target.clone()) {
            continue;
        }
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&trace.target)?;
    }
    Ok(())
}

pub fn dump(transfer: &TransferConfig, event: TraceEvent, data: &[u8]) -> Result<()> {
    let Some(trace) = &transfer.trace else {
        return Ok(());
    };

    write_to_target(trace, |writer| {
        write_title(writer, trace, event, data.len())?;
        match trace.mode {
            TraceMode::Ascii => write_ascii_dump(writer, data)?,
            TraceMode::Binary => write_binary_dump(writer, data)?,
        }
        Ok(())
    })?;
    Ok(())
}

pub fn dump_http_request(transfer: &TransferConfig, request: &[u8]) -> Result<()> {
    let (header, body) = split_http_message(request);
    dump(transfer, TraceEvent::SendHeader, header)?;
    if !body.is_empty() {
        dump(transfer, TraceEvent::SendData, body)?;
    }
    Ok(())
}

fn split_http_message(message: &[u8]) -> (&[u8], &[u8]) {
    if let Some(index) = find_bytes(message, b"\r\n\r\n") {
        let split = index + 4;
        (&message[..split], &message[split..])
    } else if let Some(index) = find_bytes(message, b"\n\n") {
        let split = index + 2;
        (&message[..split], &message[split..])
    } else {
        (message, &[])
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn write_to_target<F>(trace: &TraceConfig, write: F) -> io::Result<()>
where
    F: FnOnce(&mut dyn Write) -> io::Result<()>,
{
    match trace.target.as_str() {
        "-" => {
            let stdout = io::stdout();
            let mut stdout = stdout.lock();
            write(&mut stdout)
        }
        "%" => {
            let stderr = io::stderr();
            let mut stderr = stderr.lock();
            write(&mut stderr)
        }
        path => {
            let mut file = OpenOptions::new().create(true).append(true).open(path)?;
            write(&mut file)
        }
    }
}

fn write_title(
    writer: &mut dyn Write,
    trace: &TraceConfig,
    event: TraceEvent,
    size: usize,
) -> io::Result<()> {
    if trace.time {
        write!(writer, "{} ", trace_time_prefix())?;
    }
    writeln!(writer, "{}, {} bytes (0x{:x})", event.label(), size, size)
}

fn trace_time_prefix() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let micros = now.subsec_micros();
    let seconds = now.as_secs() % 86_400;
    let hours = seconds / 3_600;
    let minutes = (seconds % 3_600) / 60;
    let seconds = seconds % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}.{micros:06}")
}

fn write_ascii_dump(writer: &mut dyn Write, data: &[u8]) -> io::Result<()> {
    let mut offset = 0;
    while offset < data.len() {
        let row_offset = offset;
        write!(writer, "{row_offset:04x}: ")?;
        let mut count = 0;
        while offset < data.len() && count < ASCII_WIDTH {
            if is_crlf_at(data, offset) {
                offset += 2;
                break;
            }
            writer.write_all(&[printable_byte(data[offset])])?;
            offset += 1;
            count += 1;
            if is_crlf_at(data, offset) {
                offset += 2;
                break;
            }
        }
        writer.write_all(b"\n")?;
    }
    Ok(())
}

fn write_binary_dump(writer: &mut dyn Write, data: &[u8]) -> io::Result<()> {
    for (row, chunk) in data.chunks(BINARY_WIDTH).enumerate() {
        write!(writer, "{:04x}: ", row * BINARY_WIDTH)?;
        for byte in chunk {
            write!(writer, "{byte:02x} ")?;
        }
        for _ in chunk.len()..BINARY_WIDTH {
            writer.write_all(b"   ")?;
        }
        writer.write_all(b" ")?;
        for byte in chunk {
            writer.write_all(&[printable_byte(*byte)])?;
        }
        writer.write_all(b"\n")?;
    }
    Ok(())
}

fn is_crlf_at(data: &[u8], offset: usize) -> bool {
    data.get(offset..offset + 2) == Some(b"\r\n")
}

fn printable_byte(byte: u8) -> u8 {
    if byte.is_ascii_graphic() || byte == b' ' {
        byte
    } else {
        b'.'
    }
}

fn is_standard_stream(target: &str) -> bool {
    target == "-" || target == "%"
}
