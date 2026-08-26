use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

fn main() -> io::Result<()> {
    let mut args = env::args().skip(1);
    let log = PathBuf::from(args.next().expect("fixture log path"));
    let crash_marker = args.next().map(PathBuf::from);
    let stdin = io::stdin();
    let mut input = BufReader::new(stdin.lock());
    let mut output = io::stdout().lock();
    let mut hang = false;
    let mut server_error = false;
    let mut document_uri = None;

    while let Some(body) = read_message(&mut input)? {
        append_log(&log, &body)?;
        if body.contains("\"method\":\"textDocument/didOpen\"")
            || body.contains("\"method\":\"textDocument/didChange\"")
        {
            hang = body.contains("HANG");
            server_error = body.contains("SERVER_ERROR");
            if body.contains("\"method\":\"textDocument/didOpen\"") {
                document_uri = json_string_member(&body, "uri");
            }
            continue;
        }
        if body.contains("\"method\":\"initialized\"")
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
        let result = if body.contains("\"method\":\"initialize\"") {
            r#"{"capabilities":{"textDocumentSync":1,"callHierarchyProvider":true},"serverInfo":{"name":"compiled-fixture","version":"1.0.0"}}"#.to_string()
        } else if body.contains("\"method\":\"shutdown\"") {
            "null".to_string()
        } else if body.contains("\"method\":\"textDocument/prepareCallHierarchy\"") {
            format!(
                r#"[{{"name":"target","kind":12,"detail":"complete fixture item","uri":"{}","range":{{"start":{{"line":0,"character":0}},"end":{{"line":2,"character":1}}}},"selectionRange":{{"start":{{"line":0,"character":3}},"end":{{"line":0,"character":9}}}},"data":{{"opaque":{{"fixture":true,"sequence":7}}}}}}]"#,
                document_uri.as_deref().expect("didOpen URI")
            )
        } else if body.contains("\"method\":\"callHierarchy/incomingCalls\"") {
            if !body.contains("\"opaque\":{\"fixture\":true,\"sequence\":7}")
                && !body.contains("\"roundtrip\":\"incoming\"")
            {
                write_error(
                    &mut output,
                    id,
                    -32602,
                    "opaque item data was not preserved",
                )?;
                continue;
            }
            format!(
                r#"[{{"from":{{"name":"caller","kind":12,"uri":"{}","range":{{"start":{{"line":3,"character":0}},"end":{{"line":4,"character":1}}}},"selectionRange":{{"start":{{"line":3,"character":2}},"end":{{"line":3,"character":8}}}},"data":{{"roundtrip":"incoming"}}}},"fromRanges":[]}}]"#,
                document_uri.as_deref().expect("didOpen URI")
            )
        } else if body.contains("\"method\":\"callHierarchy/outgoingCalls\"") {
            if !body.contains("\"opaque\":{\"fixture\":true,\"sequence\":7}") {
                write_error(
                    &mut output,
                    id,
                    -32602,
                    "opaque item data was not preserved",
                )?;
                continue;
            }
            format!(
                r#"[{{"to":{{"name":"callee","kind":12,"uri":"{}","range":{{"start":{{"line":5,"character":0}},"end":{{"line":6,"character":1}}}},"selectionRange":{{"start":{{"line":5,"character":2}},"end":{{"line":5,"character":8}}}},"data":{{"roundtrip":"outgoing"}}}},"fromRanges":[]}}]"#,
                document_uri.as_deref().expect("didOpen URI")
            )
        } else if body.contains("\"method\":\"textDocument/hover\"") {
            if let Some(marker) = crash_marker.as_ref() {
                if !marker.exists() {
                    fs::write(marker, "crashed")?;
                    return Ok(());
                }
            }
            while hang {
                thread::sleep(Duration::from_millis(50));
            }
            if server_error {
                write_error(&mut output, id, -32_002, "fixture server error")?;
                continue;
            }
            r#"{"contents":{"kind":"plaintext","value":"fixture-hover"}}"#.to_string()
        } else if body.contains("\"method\":\"workspace/symbol\"") {
            format!(
                r#"[{{"name":"FixtureSymbol","kind":12,"containerName":"fixture","location":{{"uri":"{}","range":{{"start":{{"line":0,"character":0}},"end":{{"line":0,"character":7}}}}}}}}]"#,
                document_uri.as_deref().expect("didOpen URI")
            )
        } else {
            "[]".to_string()
        };
        write_result(&mut output, id, &result)?;
    }
    Ok(())
}

fn json_string_member(body: &str, name: &str) -> Option<String> {
    let marker = format!(r#""{name}":""#);
    let tail = body.split_once(&marker)?.1;
    let value = tail.split_once('"')?.0;
    Some(value.to_string())
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

fn append_log(path: &PathBuf, body: &str) -> io::Result<()> {
    let mut log = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(log, "pid={}\t{body}", std::process::id())
}

fn write_result(output: &mut impl Write, id: u64, result: &str) -> io::Result<()> {
    write_message(
        output,
        &format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{result}}}"#),
    )
}

fn write_error(output: &mut impl Write, id: u64, code: i64, message: &str) -> io::Result<()> {
    write_message(
        output,
        &format!(
            r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":{code},"message":"{message}"}}}}"#
        ),
    )
}

fn write_message(output: &mut impl Write, body: &str) -> io::Result<()> {
    write!(output, "Content-Length: {}\r\n\r\n{body}", body.len())?;
    output.flush()
}
