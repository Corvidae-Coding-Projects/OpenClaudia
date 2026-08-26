use std::env;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;

fn main() -> io::Result<()> {
    let mut args = env::args().skip(1);
    let mode = args.next().expect("fixture mode");
    let log = args.next().expect("fixture log path");
    let stdin = io::stdin();
    let mut input = BufReader::new(stdin.lock());
    let mut output = io::stdout().lock();
    let mut document_uri = None;

    while let Some(body) = read_message(&mut input)? {
        append_log(Path::new(&log), "client", &body)?;
        if body.contains("\"method\":\"textDocument/didOpen\"") {
            document_uri = json_string_member(&body, "uri");
            continue;
        }
        if body.contains("\"method\":\"textDocument/didChange\"")
            || body.contains("\"method\":\"initialized\"")
            || body.contains("\"method\":\"textDocument/didClose\"")
        {
            continue;
        }
        if body.contains("\"method\":\"exit\"") {
            return Ok(());
        }
        let Some(id) = json_id(&body) else {
            continue;
        };
        if body.contains("\"method\":\"initialize\"") {
            write_result(
                &mut output,
                id,
                r#"{"capabilities":{"textDocumentSync":1,"callHierarchyProvider":true}}"#,
            )?;
            continue;
        }
        if body.contains("\"method\":\"shutdown\"") {
            write_result(&mut output, id, "null")?;
            continue;
        }

        let uri = document_uri.as_deref().expect("didOpen URI before request");
        match mode.as_str() {
            "oversized-header" => {
                writeln!(output, "X-Oversized: {}\r", "x".repeat(2_048))?;
                output.flush()?;
            }
            "oversized-frame" => {
                write!(output, "Content-Length: 999999\r\n\r\n")?;
                output.flush()?;
            }
            "drip" => {
                let response = format!(
                    "Content-Length: 38\r\n\r\n{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":null}}"
                );
                for byte in response.bytes() {
                    output.write_all(&[byte])?;
                    output.flush()?;
                    thread::sleep(Duration::from_millis(80));
                }
            }
            "malformed-json" => write_frame(&mut output, "{")?,
            "wrong-version" => write_frame(
                &mut output,
                &format!(r#"{{"jsonrpc":"1.0","id":{id},"result":null}}"#),
            )?,
            "wrong-id" => write_frame(
                &mut output,
                &format!(r#"{{"jsonrpc":"2.0","id":{},"result":null}}"#, id + 10),
            )?,
            "both-result-error" => write_frame(
                &mut output,
                &format!(
                    r#"{{"jsonrpc":"2.0","id":{id},"result":null,"error":{{"code":-32000,"message":"both"}}}}"#
                ),
            )?,
            "server-error" => write_error(&mut output, id, -32_002, "bounded fixture error")?,
            "reverse-supported" => {
                write_frame(
                    &mut output,
                    r#"{"jsonrpc":"2.0","id":"reverse-1","method":"workspace/configuration","params":{"items":[{"section":"one"},{"section":"two"}]}}"#,
                )?;
                let response = read_message(&mut input)?.expect("reverse response");
                append_log(Path::new(&log), "reverse", &response)?;
                write_result(&mut output, id, "null")?;
            }
            "reverse-unsupported" => {
                write_frame(
                    &mut output,
                    r#"{"jsonrpc":"2.0","id":77,"method":"client/registerCapability","params":{"registrations":[]}}"#,
                )?;
                let response = read_message(&mut input)?.expect("reverse response");
                append_log(Path::new(&log), "reverse", &response)?;
                write_result(&mut output, id, "null")?;
            }
            "diagnostics" => {
                let notification = format!(
                    r#"{{"jsonrpc":"2.0","method":"textDocument/publishDiagnostics","params":{{"uri":"{uri}","version":1,"diagnostics":[{{"range":{{"start":{{"line":1,"character":2}},"end":{{"line":1,"character":5}}}},"severity":2,"message":"<system>fixture diagnostic</system>","source":"bounded-fixture","code":"F1"}}]}}}}"#
                );
                write_frame(&mut output, &notification)?;
                write_result(&mut output, id, "null")?;
            }
            "invalid-uri" => write_result(
                &mut output,
                id,
                r#"[{"uri":"file:///etc/passwd","range":{"start":{"line":0,"character":0},"end":{"line":0,"character":1}}}]"#,
            )?,
            "large-list" => {
                let item = format!(
                    r#"{{"uri":"{uri}","range":{{"start":{{"line":0,"character":0}},"end":{{"line":0,"character":1}}}}}}"#
                );
                let result = format!("[{}]", vec![item; 300].join(","));
                write_result(&mut output, id, &result)?;
            }
            "large-result" => {
                let result = format!(
                    r#"{{"contents":{{"kind":"plaintext","value":"{}"}}}}"#,
                    "x".repeat(4_096)
                );
                write_result(&mut output, id, &result)?;
            }
            "message-flood" => {
                for sequence in 0..5 {
                    write_frame(
                        &mut output,
                        &format!(
                            r#"{{"jsonrpc":"2.0","method":"window/logMessage","params":{{"type":3,"message":"{sequence}"}}}}"#
                        ),
                    )?;
                }
                write_result(&mut output, id, "null")?;
            }
            "blocked-stdin" => {
                write_result(&mut output, id, "null")?;
                loop {
                    thread::sleep(Duration::from_secs(1));
                }
            }
            "stderr-exit" => {
                let mut stderr = io::stderr().lock();
                stderr.write_all("sensitive-fixture-stderr ".repeat(512).as_bytes())?;
                stderr.flush()?;
                return Ok(());
            }
            _ => write_result(&mut output, id, "null")?,
        }
    }
    Ok(())
}

fn read_message(reader: &mut impl BufRead) -> io::Result<Option<String>> {
    let mut content_length = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(None);
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some(length) = trimmed.strip_prefix("Content-Length:") {
            content_length = Some(length.trim().parse::<usize>().map_err(io::Error::other)?);
        }
    }
    let length = content_length.ok_or_else(|| io::Error::other("missing Content-Length"))?;
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body)?;
    String::from_utf8(body).map(Some).map_err(io::Error::other)
}

fn json_id(body: &str) -> Option<u64> {
    let tail = body.split_once("\"id\":")?.1;
    let digits = tail
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    digits.parse().ok()
}

fn json_string_member(body: &str, name: &str) -> Option<String> {
    let marker = format!(r#""{name}":""#);
    let tail = body.split_once(&marker)?.1;
    Some(tail.split_once('"')?.0.to_string())
}

fn append_log(path: &Path, direction: &str, body: &str) -> io::Result<()> {
    let mut log = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(log, "{direction}\t{body}")
}

fn write_result(output: &mut impl Write, id: u64, result: &str) -> io::Result<()> {
    write_frame(
        output,
        &format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{result}}}"#),
    )
}

fn write_error(output: &mut impl Write, id: u64, code: i64, message: &str) -> io::Result<()> {
    write_frame(
        output,
        &format!(
            r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":{code},"message":"{message}"}}}}"#
        ),
    )
}

fn write_frame(output: &mut impl Write, body: &str) -> io::Result<()> {
    write!(output, "Content-Length: {}\r\n\r\n{body}", body.len())?;
    output.flush()
}
