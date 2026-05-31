//! Browser WebRTC media forwarding integration coverage.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]

use std::{
    env,
    error::Error,
    fs::{self, File},
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[test]
#[ignore = "requires Chrome and target/release/refract; run after cargo build --release -p refract-bin"]
fn browser_tabs_exchange_media_through_refract() -> Result<(), Box<dyn Error>> {
    let chrome = chrome_path().ok_or("Google Chrome is required for browser media integration")?;
    let node = node_path().ok_or("node is required for browser media integration")?;
    let binary = release_binary_path();
    let signal_port = browser_signal_port()?;
    let cdp_port = free_tcp_port()?;
    let temp = tempfile::tempdir()?;
    let config = temp.path().join("browser.toml");
    let server_stdout = temp.path().join("server.stdout.log");
    let server_stderr = temp.path().join("server.stderr.log");
    fs::write(&config, config_body(signal_port))?;

    let mut server = ChildGuard::spawn(
        Command::new(binary).args([
            "--config",
            config
                .to_str()
                .ok_or("temporary config path must be valid utf-8")?,
        ]),
        server_stdout,
        server_stderr,
    )?;
    wait_for_capabilities(signal_port)?;

    let output = Command::new(node)
        .arg("-e")
        .arg(BROWSER_MEDIA_TEST)
        .env(
            "REFRACT_TEST_URL",
            format!("http://localhost:{signal_port}/#fake_media"),
        )
        .env("REFRACT_CHROME", chrome)
        .env("REFRACT_CDP_PORT", cdp_port.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    server.stop();
    let server_logs = server.logs()?;

    assert!(
        output.status.success(),
        "browser media integration failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !server_logs.contains("Failed to decrypt SRTP"),
        "server routed RTP into the wrong SRTP context\nserver logs:\n{server_logs}"
    );
    Ok(())
}

struct ChildGuard {
    child: Child,
    stdout: PathBuf,
    stderr: PathBuf,
}

impl ChildGuard {
    fn spawn(
        command: &mut Command,
        stdout: PathBuf,
        stderr: PathBuf,
    ) -> Result<Self, Box<dyn Error>> {
        let stdout_file = File::create(&stdout)?;
        let stderr_file = File::create(&stderr)?;
        let child = command
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .spawn()?;
        Ok(Self {
            child,
            stdout,
            stderr,
        })
    }

    fn stop(&mut self) {
        let _killed = self.child.kill().is_ok();
        let _waited = self.child.wait().is_ok();
    }

    fn logs(&self) -> Result<String, Box<dyn Error>> {
        let stdout = fs::read_to_string(&self.stdout)?;
        let stderr = fs::read_to_string(&self.stderr)?;
        Ok(format!("{stdout}\n{stderr}"))
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

fn chrome_path() -> Option<PathBuf> {
    env::var_os("REFRACT_CHROME")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .or_else(|| {
            [
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/usr/bin/google-chrome",
                "/usr/bin/google-chrome-stable",
                "/usr/bin/chromium",
                "/usr/bin/chromium-browser",
            ]
            .into_iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
        })
}

fn node_path() -> Option<PathBuf> {
    env::var_os("REFRACT_NODE")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .or_else(|| {
            env::var_os("PATH").and_then(|paths| {
                env::split_paths(&paths)
                    .map(|path| path.join("node"))
                    .find(|path| path.is_file())
            })
        })
}

fn release_binary_path() -> PathBuf {
    env::var_os("REFRACT_RELEASE_BIN").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/release/refract"),
        PathBuf::from,
    )
}

fn free_tcp_port() -> Result<u16, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

fn browser_signal_port() -> Result<u16, Box<dyn Error>> {
    env::var("REFRACT_BROWSER_SIGNAL_PORT").map_or_else(
        |_| free_tcp_port(),
        |value| value.parse().map_err(Into::into),
    )
}

fn wait_for_capabilities(port: u16) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if http_get(port, "/capabilities").is_ok_and(|body| {
            body.contains("\"signaling_websocket\":true")
                && body.contains("\"webrtc_media_forwarding\":true")
        }) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err("refract capabilities endpoint did not become ready".into())
}

fn http_get(port: u16, path: &str) -> Result<String, Box<dyn Error>> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let (_head, body) = response
        .split_once("\r\n\r\n")
        .ok_or("http response missing header terminator")?;
    Ok(body.to_owned())
}

fn config_body(port: u16) -> String {
    let rtcp_port = port.saturating_add(1);
    format!(
        r#"
[runtime]
cores = 1
pinning = false
hugepages = false

[net]
bind_addrs = ["127.0.0.1:{port}"]
rtp_port = {port}
rtcp_port = {rtcp_port}
mtu = 1200

[crypto]
cert_path = "certs/refract.pem"
dtls_timeout_ms = 1000

[cluster]
peer_addrs = []

[cluster.raft]
node_id = 1
election_timeout_ms = 1500
heartbeat_ms = 250

[obs]
metric_exporter_targets = []

[apps.echo]
enabled = true
max_sessions = 64

[apps.echo.settings]
mode = "loopback"
"#
    )
}

const BROWSER_MEDIA_TEST: &str = r#"
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const chromePath = process.env.REFRACT_CHROME;
const targetUrl = process.env.REFRACT_TEST_URL;
const port = Number(process.env.REFRACT_CDP_PORT);
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'refract-chrome-'));
const chrome = spawn(chromePath, [
  `--remote-debugging-port=${port}`,
  `--user-data-dir=${userDataDir}`,
  '--headless=new',
  '--use-fake-device-for-media-stream',
  '--use-fake-ui-for-media-stream',
  '--autoplay-policy=no-user-gesture-required',
  '--no-first-run',
  '--no-default-browser-check'
], { stdio: ['ignore', 'ignore', 'ignore'] });

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function waitForChrome() {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/version`);
      if (response.ok) return;
    } catch (_error) {
      await sleep(100);
    }
  }
  throw new Error('chrome remote debugging endpoint did not start');
}

async function newTab(url) {
  const response = await fetch(
    `http://127.0.0.1:${port}/json/new?${encodeURIComponent(url)}`,
    { method: 'PUT' }
  );
  if (!response.ok) throw new Error(`new tab failed: ${response.status}`);
  return await response.json();
}

function connect(wsUrl) {
  const ws = new WebSocket(wsUrl);
  let nextId = 1;
  const pending = new Map();
  ws.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (!message.id) return;
    const callback = pending.get(message.id);
    if (!callback) return;
    pending.delete(message.id);
    if (message.error) callback.reject(new Error(`${message.error.code}: ${message.error.message}`));
    else callback.resolve(message.result);
  });
  return new Promise((resolve, reject) => {
    ws.addEventListener('open', () => {
      resolve({
        send(method, params = {}) {
          const id = nextId;
          nextId += 1;
          ws.send(JSON.stringify({ id, method, params }));
          return new Promise((sendResolve, sendReject) => {
            pending.set(id, { resolve: sendResolve, reject: sendReject });
          });
        },
        close() {
          ws.close();
        }
      });
    }, { once: true });
    ws.addEventListener('error', reject, { once: true });
  });
}

async function evaluate(client, expression) {
  const result = await client.send('Runtime.evaluate', {
    expression,
    awaitPromise: true,
    returnByValue: true,
    userGesture: true
  });
  if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
  return result.result.value;
}

async function waitForReady(client) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const ready = await evaluate(
      client,
      'document.readyState === "complete" || document.readyState === "interactive"'
    );
    if (ready) return;
    await sleep(100);
  }
  throw new Error('page did not become ready');
}

async function sample(client) {
  return await evaluate(client, `(async () => {
    const text = document.getElementById('status').textContent;
    const appLines = text.split('\\n').filter(line => line.startsWith('{"app"'));
    return {
      tracks: window.refractDebug.remoteTrackCount(),
      inbound: await window.refractDebug.inboundRtpPackets(),
      outbound: await window.refractDebug.outboundRtpPackets(),
      connection: window.refractDebug.connectionState(),
      ice: window.refractDebug.iceConnectionState(),
      appMessages: appLines.length,
      failedMessages: appLines.filter(line => line.includes('"ok":false')).length,
      answerMessages: appLines.filter(line => line.includes('"type":"rtc_answer"')).length
    };
  })()`);
}

async function enableClient(client) {
  await Promise.all([
    client.send('Runtime.enable'),
    client.send('Page.enable')
  ]);
  await waitForReady(client);
}

async function joinClients(clients) {
  await Promise.all(clients.map(client =>
    evaluate(client, 'document.getElementById("join").click(); true')
  ));
}

async function requestKeyframes(clients) {
  await Promise.all(clients.map(client =>
    evaluate(client, 'window.refractDebug.requestKeyframes(); true')
  ));
}

async function waitForMedia(clients, baselines) {
  const samples = [];
  for (let secondIndex = 1; secondIndex <= 25; secondIndex += 1) {
    await requestKeyframes(clients);
    await sleep(1000);
    const values = await Promise.all(clients.map(sample));
    const current = { second: secondIndex, values };
    samples.push(current);
    if (values.every((value, index) =>
      value.tracks > 0 &&
      value.inbound > baselines[index].inbound &&
      value.failedMessages === 0
    )) {
      return { ok: true, samples, final: current };
    }
  }
  return { ok: false, samples, final: samples[samples.length - 1] };
}

async function waitForReplacement(clients, baselines) {
  const samples = [];
  const replacementIndex = clients.length - 1;
  for (let secondIndex = 1; secondIndex <= 25; secondIndex += 1) {
    await requestKeyframes(clients);
    await sleep(1000);
    const values = await Promise.all(clients.map(sample));
    const current = { second: secondIndex, values };
    samples.push(current);
    const replacement = values[replacementIndex];
    const anySurvivorAdvanced = values
      .slice(0, replacementIndex)
      .some((value, index) => value.inbound > baselines[index].inbound);
    if (
      replacement.tracks > 0 &&
      replacement.inbound > baselines[replacementIndex].inbound &&
      anySurvivorAdvanced &&
      values.every(value => value.failedMessages === 0)
    ) {
      return { ok: true, samples, final: current };
    }
  }
  return { ok: false, samples, final: samples[samples.length - 1] };
}

async function closeTab(target, client) {
  try {
    await fetch(`http://127.0.0.1:${port}/json/close/${target.id}`);
  } catch (_error) {}
  client.close();
  await sleep(500);
}

async function run() {
  await waitForChrome();
  const first = await newTab(targetUrl);
  const second = await newTab(targetUrl);
  const third = await newTab(targetUrl);
  const a = await connect(first.webSocketDebuggerUrl);
  const b = await connect(second.webSocketDebuggerUrl);
  const c = await connect(third.webSocketDebuggerUrl);
  await Promise.all([enableClient(a), enableClient(b), enableClient(c)]);
  const baseline = await Promise.all([sample(a), sample(b), sample(c)]);
  await joinClients([a, b, c]);

  const phaseOne = await waitForMedia([a, b, c], baseline);
  await closeTab(first, a);

  const fourth = await newTab(targetUrl);
  const d = await connect(fourth.webSocketDebuggerUrl);
  await enableClient(d);
  const replacementBaseline = await Promise.all([sample(b), sample(c), sample(d)]);
  await joinClients([d]);
  const phaseTwo = await waitForReplacement([b, c, d], replacementBaseline);

  await Promise.all([closeTab(second, b), closeTab(third, c), closeTab(fourth, d)]);
  const ok = phaseOne.ok && phaseTwo.ok;
  console.log(JSON.stringify({ ok, baseline, phaseOne, replacementBaseline, phaseTwo }, null, 2));
  if (!ok) process.exitCode = 1;
}

run().catch(error => {
  console.error(error && error.stack ? error.stack : error);
  process.exitCode = 1;
}).finally(async () => {
  chrome.kill('SIGTERM');
  await new Promise(resolve => chrome.once('exit', resolve));
  try {
    fs.rmSync(userDataDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  } catch (_error) {}
});
"#;
