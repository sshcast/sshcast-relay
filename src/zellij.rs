use anyhow::{Context, Result};
use sshcast_proto::crypto::{
    create_node_auth, sign_zellij_tunnel_frame, verify_zellij_tunnel_frame,
};
use sshcast_proto::p2p::{
    build_stun_binding_request, derive_p2p_session_keys, parse_stun_binding_response,
    P2pEndpointHandshake, P2pStreamCipher,
};
use sshcast_proto::v1::relay_stream_message::Payload as RelayOutPayload;
use sshcast_proto::v1::server_to_relay_message::Payload as ServerInPayload;
use sshcast_proto::v1::sshcast_service_client::SshcastServiceClient;
use sshcast_proto::v1::{
    NodeRole, RelayStreamMessage, RelayZellijStatus, ZellijFrameType, ZellijSessionInfo,
    ZellijTunnelFrame,
};
use std::collections::HashMap;
use std::io::Read as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch, Mutex};
use tonic::codegen::tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{ClientTlsConfig, Endpoint};

use crate::config::{home_dir, RelayConfig};

/// Ensures `web_sharing "on"` is present in the given Zellij `config.kdl` file so sessions
/// started from interactive terminal shells (`zellij` / `zellij attach -c`) allow web clients to attach.
/// Returns `Ok(true)` if the file was created or updated, or `Ok(false)` if `web_sharing "on"` was already set.
pub fn ensure_zellij_web_sharing_in_file(config_path: &Path) -> Result<bool> {
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    if !config_path.exists() {
        std::fs::write(config_path, "web_sharing \"on\"\n")
            .with_context(|| format!("failed to write {}", config_path.display()))?;
        return Ok(true);
    }

    let raw = std::fs::read_to_string(config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;

    let mut found_active = false;
    let mut already_on = false;
    let mut updated_lines = Vec::new();

    for line in raw.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("//") && trimmed.starts_with("web_sharing") {
            let after = trimmed.trim_start_matches("web_sharing").trim();
            if after.starts_with('"') {
                found_active = true;
                if after.starts_with("\"on\"") {
                    already_on = true;
                    updated_lines.push(line.to_string());
                } else {
                    updated_lines.push("web_sharing \"on\"".to_string());
                }
                continue;
            }
        }
        updated_lines.push(line.to_string());
    }

    if already_on {
        return Ok(false);
    }

    let new_contents = if found_active {
        let mut s = updated_lines.join("\n");
        s.push('\n');
        s
    } else {
        let mut s = raw;
        if !s.is_empty() && !s.ends_with('\n') {
            s.push('\n');
        }
        s.push_str("web_sharing \"on\"\n");
        s
    };

    std::fs::write(config_path, new_contents)
        .with_context(|| format!("failed to update {}", config_path.display()))?;
    Ok(true)
}

/// Resolves `~/.config/zellij/config.kdl` (or `$XDG_CONFIG_HOME/zellij/config.kdl`) and ensures
/// `web_sharing "on"` is configured so CLI-started Zellij sessions allow web clients to attach.
pub fn ensure_zellij_web_sharing_enabled() -> Result<Option<PathBuf>> {
    let base_dir = if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            PathBuf::from(xdg)
        } else {
            home_dir()?.join(".config")
        }
    } else {
        home_dir()?.join(".config")
    };
    let config_path = base_dir.join("zellij").join("config.kdl");
    let modified = ensure_zellij_web_sharing_in_file(&config_path)?;
    if modified {
        tracing::info!(
            "Configured `web_sharing \"on\"` in {} so terminal Zellij sessions allow web attach",
            config_path.display()
        );
        Ok(Some(config_path))
    } else {
        Ok(None)
    }
}

fn now_unix_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Parses the plain (`-n` / `--no-formatting`) output of `zellij list-sessions -n`.
pub fn parse_zellij_list_sessions_output(raw: &str) -> Vec<ZellijSessionInfo> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("No active zellij sessions") {
            continue;
        }
        let mut parts = trimmed.splitn(2, char::is_whitespace);
        let Some(name) = parts.next() else {
            continue;
        };
        let rest = parts.next().unwrap_or("").trim();
        let exited = rest.contains("EXITED");
        out.push(ZellijSessionInfo {
            name: name.to_string(),
            created_info: rest.to_string(),
            exited,
        });
    }
    out
}

/// Runs `zellij list-sessions -n` to discover active and resurrectable Zellij sessions on this host.
pub fn discover_zellij_sessions() -> Vec<ZellijSessionInfo> {
    let output = Command::new("zellij")
        .args(["list-sessions", "-n"])
        .stdin(Stdio::null())
        .output();
    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            parse_zellij_list_sessions_output(&stdout)
        }
        Err(_) => Vec::new(),
    }
}

/// Parses `zellij web --create-token` output (e.g. `token_1: <uuid>`) to extract the login token.
pub fn parse_zellij_create_token_output(raw: &str) -> Option<String> {
    for line in raw.lines() {
        let trimmed = line.trim();
        if let Some((prefix, rest)) = trimmed.split_once(':') {
            if prefix.trim().starts_with("token_") {
                let tok = rest.trim();
                if !tok.is_empty() {
                    return Some(tok.to_string());
                }
            }
        }
    }
    None
}

/// Rewrites the first HTTP request header block destined for `127.0.0.1:<web_port>`:
/// - Sets `Host: 127.0.0.1:<web_port>`
/// - Rewrites `Origin:` (if present) to `http://127.0.0.1:<web_port>`
/// - Injects `session_token=<val>` into `Cookie:` so `zellij web` never prompts the user for a token.
/// - Forces `Connection: close` on non-WebSocket requests so each HTTP asset request uses a clean
///   1-request-per-tunnel lifecycle while WebSockets keep `Connection: Upgrade`.
pub fn rewrite_http_request_for_zellij_web(
    buf: &[u8],
    web_port: u16,
    session_cookie: Option<&str>,
) -> Vec<u8> {
    let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return buf.to_vec();
    };
    let header_str = match std::str::from_utf8(&buf[..header_end]) {
        Ok(s) => s,
        Err(_) => return buf.to_vec(),
    };
    let is_websocket = header_str.lines().any(|l| {
        if let Some((k, v)) = l.split_once(':') {
            k.trim().eq_ignore_ascii_case("upgrade")
                && v.to_ascii_lowercase().contains("websocket")
        } else {
            false
        }
    });

    let mut lines = header_str.split("\r\n");
    let Some(request_line) = lines.next() else {
        return buf.to_vec();
    };

    let mut out_headers = String::with_capacity(header_str.len() + 160);
    out_headers.push_str(request_line);
    out_headers.push_str("\r\n");

    let target_host = format!("127.0.0.1:{web_port}");
    let target_origin = format!("http://127.0.0.1:{web_port}");
    let mut saw_host = false;
    let mut saw_cookie = false;
    let mut saw_connection = false;

    for line in lines {
        if let Some((name, val)) = line.split_once(':') {
            let name_trim = name.trim();
            if name_trim.eq_ignore_ascii_case("host") {
                saw_host = true;
                out_headers.push_str(&format!("Host: {target_host}\r\n"));
                continue;
            }
            if name_trim.eq_ignore_ascii_case("origin") {
                out_headers.push_str(&format!("Origin: {target_origin}\r\n"));
                continue;
            }
            if !is_websocket && name_trim.eq_ignore_ascii_case("connection") {
                saw_connection = true;
                out_headers.push_str("Connection: close\r\n");
                continue;
            }
            if name_trim.eq_ignore_ascii_case("cookie") {
                saw_cookie = true;
                let existing = val.trim();
                if let Some(cookie_kv) = session_cookie {
                    if !existing.contains("session_token=") {
                        if existing.is_empty() {
                            out_headers.push_str(&format!("Cookie: {cookie_kv}\r\n"));
                        } else {
                            out_headers.push_str(&format!("Cookie: {existing}; {cookie_kv}\r\n"));
                        }
                        continue;
                    }
                }
            }
        }
        out_headers.push_str(line);
        out_headers.push_str("\r\n");
    }

    if !saw_host {
        out_headers.push_str(&format!("Host: {target_host}\r\n"));
    }
    if !is_websocket && !saw_connection {
        out_headers.push_str("Connection: close\r\n");
    }
    if !saw_cookie {
        if let Some(cookie_kv) = session_cookie {
            out_headers.push_str(&format!("Cookie: {cookie_kv}\r\n"));
        }
    }
    out_headers.push_str("\r\n");

    let mut out = out_headers.into_bytes();
    out.extend_from_slice(&buf[header_end + 4..]);
    out
}

const WS_NORMAL_CLOSE_FRAME: &[u8; 21] = b"\x88\x13\x03\xe8Connection closed";
const WS_DISCONNECTED_CLOSE_FRAME: &[u8; 21] = b"\x88\x13\x0f\xa1Connection closed";

const SYMBOLS_NERD_FONT_TTF_GZ: &[u8] =
    include_bytes!("../assets/fonts/SymbolsNerdFontMono-Regular.ttf.gz");
const IOSEVKA_TERM_REGULAR_TTF_GZ: &[u8] =
    include_bytes!("../assets/fonts/IosevkaTerm-Regular.ttf.gz");
const IOSEVKA_TERM_BOLD_TTF_GZ: &[u8] = include_bytes!("../assets/fonts/IosevkaTerm-Bold.ttf.gz");

const SSHCAST_FONTS_CSS: &str = r#"@font-face {
  font-family: "Symbols Nerd Font Mono";
  src: url("/__sshcast/SymbolsNerdFontMono-Regular.ttf") format("truetype");
  font-weight: 100 900;
  font-style: normal;
  font-display: block;
}
@font-face {
  font-family: "Symbols Nerd Font Mono";
  src: url("/__sshcast/SymbolsNerdFontMono-Regular.ttf") format("truetype");
  font-weight: 100 900;
  font-style: italic;
  font-display: block;
}
@font-face {
  font-family: "Iosevka Term";
  src: url("/__sshcast/IosevkaTerm-Regular.ttf") format("truetype");
  font-weight: 400;
  font-style: normal;
  font-display: block;
}
@font-face {
  font-family: "Iosevka Term";
  src: url("/__sshcast/IosevkaTerm-Bold.ttf") format("truetype");
  font-weight: 700;
  font-style: normal;
  font-display: block;
}
"#;

const SSHCAST_ZELLIJ_JS: &str = r#"(function () {
  const SSHCAST_DEFAULT_FONT_STACK =
    '"Iosevka Term", "Symbols Nerd Font Mono", "Cascadia Mono", Consolas, "Liberation Mono", Menlo, monospace';

  function withSshcastNerdFonts(rawFont) {
    if (
      typeof rawFont !== "string" ||
      !rawFont.trim() ||
      rawFont.trim().toLowerCase() === "monospace"
    ) {
      return SSHCAST_DEFAULT_FONT_STACK;
    }
    const parts = rawFont
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const withoutGenericAndBundled = parts.filter((p) => {
      const norm = p.replace(/['"]/g, "").trim().toLowerCase();
      return (
        norm !== "monospace" &&
        norm !== "symbols nerd font mono" &&
        norm !== "iosevka term"
      );
    });
    return [
      ...withoutGenericAndBundled,
      '"Symbols Nerd Font Mono"',
      '"Iosevka Term"',
      "monospace",
    ].join(", ");
  }

  function preloadSshcastFonts() {
    if (!document.fonts || typeof document.fonts.load !== "function") {
      return Promise.resolve();
    }
    const loads = Promise.allSettled([
      document.fonts.load('400 12px "Iosevka Term"'),
      document.fonts.load('700 12px "Iosevka Term"'),
      document.fonts.load('400 12px "Symbols Nerd Font Mono"'),
      document.fonts.load('700 12px "Symbols Nerd Font Mono"'),
    ]);
    const timeout = new Promise((resolve) => setTimeout(resolve, 1500));
    return Promise.race([loads, timeout]);
  }

  const fontPreloadPromise = preloadSshcastFonts();

  if (typeof window.fetch === "function") {
    const origFetch = window.fetch.bind(window);
    window.fetch = async function (input, init) {
      const urlStr =
        typeof input === "string"
          ? input
          : input && typeof input.url === "string"
          ? input.url
          : "";
      const isSessionBoot =
        urlStr.includes("/session") && !urlStr.includes("/session-list");
      if (isSessionBoot) {
        const [resp] = await Promise.all([
          origFetch(input, init),
          fontPreloadPromise,
        ]);
        try {
          const clone = resp.clone();
          const data = await clone.json();
          if (data && typeof data === "object") {
            data.config = data.config || {};
            data.config.font = withSshcastNerdFonts(data.config.font);
            return new Response(JSON.stringify(data), {
              status: resp.status,
              statusText: resp.statusText,
              headers: resp.headers,
            });
          }
        } catch (_) {}
        return resp;
      }
      return origFetch(input, init);
    };
  }

  function refreshTermFontAtlas(term) {
    if (!term) return;
    try {
      if (typeof term.clearTextureAtlas === "function") {
        term.clearTextureAtlas();
      }
      if (typeof term.refresh === "function" && term.rows > 0) {
        term.refresh(0, term.rows - 1);
      }
    } catch (_) {}
  }

  if (typeof window.Terminal === "function") {
    const OrigTerminal = window.Terminal;
    window.Terminal = new Proxy(OrigTerminal, {
      construct(Target, args, newTarget) {
        const opts = Object.assign({}, args[0] || {});
        opts.fontFamily = withSshcastNerdFonts(opts.fontFamily);
        const term = Reflect.construct(Target, [opts, ...args.slice(1)], newTarget);
        if (term && term._publicOptions) {
          term._publicOptions = new Proxy(term._publicOptions, {
            set(target, prop, value) {
              if (prop === "fontFamily") {
                value = withSshcastNerdFonts(value);
              }
              target[prop] = value;
              return true;
            },
          });
        }
        fontPreloadPromise.then(() => refreshTermFontAtlas(term));
        if (document.fonts && typeof document.fonts.addEventListener === "function") {
          document.fonts.addEventListener("loadingdone", () =>
            refreshTermFontAtlas(term)
          );
        }
        return term;
      },
    });
  }

  function installExitModalHook() {
    const origShowError = window.showErrorModal;
    if (typeof origShowError === "function" && !origShowError.__sshcastWrapped) {
      const wrapped = async function (title, desc) {
        if (title === "Disconnected") {
          let screenText = "";
          try {
            if (window.term && window.term.buffer && window.term.buffer.active) {
              const buf = window.term.buffer.active;
              for (let r = 0; r < buf.length; r++) {
                const line = buf.getLine(r);
                if (line) screenText += line.translateToString(true) + "\n";
              }
            }
          } catch (_) {}
          if (screenText.includes("Web Clients are not allowed to attach")) {
            await origShowError(
              "Web Sharing Disabled in Session",
              'This session was started in the terminal before web_sharing "on" was enabled. Restart the session in your terminal (or enable sharing via Zellij\'s share plugin) to attach from the web.'
            );
          } else {
            await origShowError(
              "Session Ended",
              "The Zellij session has exited. Press Enter or Escape to return to the session list."
            );
          }
          const port = window.location.port ? ":" + window.location.port : "";
          window.location.href =
            window.location.protocol + "//localhost" + port + "/";
          return;
        }
        return origShowError(title, desc);
      };
      wrapped.__sshcastWrapped = true;
      window.showErrorModal = wrapped;
    }
  }

  installExitModalHook();
  window.addEventListener("DOMContentLoaded", installExitModalHook);
})();
"#;

const ZELLIJ_HTML_ASSETS_SNIPPET: &str = r#"<link rel="stylesheet" href="/__sshcast/sshcast-fonts.css" />
<script src="/__sshcast/sshcast-zellij.js"></script>
"#;

/// Serves embedded `/__sshcast/*` static assets (Nerd Font symbols, Iosevka Term fonts, CSS, and JS hooks).
/// Returns `Some(http_response_bytes)` if `req_buf` is a `GET` or `HEAD` request for `/__sshcast/*`.
pub fn try_build_sshcast_asset_http_response(req_buf: &[u8]) -> Option<Vec<u8>> {
    let header_end = req_buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let header_str = std::str::from_utf8(&req_buf[..header_end]).ok()?;
    let mut lines = header_str.split("\r\n");
    let req_line = lines.next()?;
    let mut parts = req_line.split_whitespace();
    let method = parts.next()?;
    let raw_path = parts.next()?;
    if !method.eq_ignore_ascii_case("GET") && !method.eq_ignore_ascii_case("HEAD") {
        return None;
    }
    let clean_path = raw_path.split('?').next().unwrap_or(raw_path);
    if !clean_path.starts_with("/__sshcast/") {
        return None;
    }
    let is_head = method.eq_ignore_ascii_case("HEAD");
    let accepts_gzip = header_str.lines().any(|l| {
        if let Some((k, v)) = l.split_once(':') {
            k.trim().eq_ignore_ascii_case("accept-encoding")
                && v.to_ascii_lowercase().contains("gzip")
        } else {
            false
        }
    });

    enum AssetBody<'a> {
        Plain(&'a [u8]),
        GzipFont(&'a [u8]),
    }

    let (content_type, cache_control, asset_body) = match clean_path {
        "/__sshcast/sshcast-fonts.css" => (
            "text/css; charset=utf-8",
            "no-cache",
            AssetBody::Plain(SSHCAST_FONTS_CSS.as_bytes()),
        ),
        "/__sshcast/sshcast-zellij.js" => (
            "application/javascript; charset=utf-8",
            "no-cache",
            AssetBody::Plain(SSHCAST_ZELLIJ_JS.as_bytes()),
        ),
        "/__sshcast/SymbolsNerdFontMono-Regular.ttf" => (
            "font/ttf",
            "public, max-age=31536000, immutable",
            AssetBody::GzipFont(SYMBOLS_NERD_FONT_TTF_GZ),
        ),
        "/__sshcast/IosevkaTerm-Regular.ttf" => (
            "font/ttf",
            "public, max-age=31536000, immutable",
            AssetBody::GzipFont(IOSEVKA_TERM_REGULAR_TTF_GZ),
        ),
        "/__sshcast/IosevkaTerm-Bold.ttf" => (
            "font/ttf",
            "public, max-age=31536000, immutable",
            AssetBody::GzipFont(IOSEVKA_TERM_BOLD_TTF_GZ),
        ),
        _ => {
            return Some(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_vec(),
            );
        }
    };

    let (body_bytes, content_encoding): (Vec<u8>, Option<&str>) = match asset_body {
        AssetBody::Plain(b) => (b.to_vec(), None),
        AssetBody::GzipFont(gz_bytes) => {
            if accepts_gzip {
                (gz_bytes.to_vec(), Some("gzip"))
            } else {
                let mut decoder = flate2::read::GzDecoder::new(gz_bytes);
                let mut raw = Vec::new();
                decoder.read_to_end(&mut raw).ok()?;
                (raw, None)
            }
        }
    };

    let encoding_header = match content_encoding {
        Some(enc) => format!("Content-Encoding: {enc}\r\nVary: Accept-Encoding\r\n"),
        None => String::new(),
    };

    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n{encoding_header}Content-Length: {}\r\nCache-Control: {cache_control}\r\nConnection: close\r\n\r\n",
        body_bytes.len()
    );
    let mut out = headers.into_bytes();
    if !is_head {
        out.extend_from_slice(&body_bytes);
    }
    Some(out)
}

/// Rewrites `zellij web`'s unmasked WebSocket `CloseFrame { code: 1000, reason: "Connection closed" }`
/// (`\x88\x13\x03\xe8Connection closed`) to close code `4001` (`\x88\x13\x0f\xa1Connection closed`).
/// Upstream `zellij web` sends close code `1000` on normal session exit (`ExitReason::Normal`),
/// which causes `app.js` (`if (event.code === 4001) handleDisconnected() else handleReconnection()`)
/// to treat a closed session as a network drop, reload `/<session>`, and immediately recreate it.
pub fn rewrite_websocket_normal_close_to_4001(buf: &mut [u8]) {
    if buf.len() < WS_NORMAL_CLOSE_FRAME.len() {
        return;
    }
    let mut i = 0;
    while i + WS_NORMAL_CLOSE_FRAME.len() <= buf.len() {
        if &buf[i..i + WS_NORMAL_CLOSE_FRAME.len()] == WS_NORMAL_CLOSE_FRAME {
            buf[i..i + WS_DISCONNECTED_CLOSE_FRAME.len()]
                .copy_from_slice(WS_DISCONNECTED_CLOSE_FRAME);
            i += WS_DISCONNECTED_CLOSE_FRAME.len();
        } else {
            i += 1;
        }
    }
}

/// Injects `Set-Cookie: session_token=...; Path=/; SameSite=Lax` (and `Connection: close` on non-101 responses)
/// into an HTTP response header block if not already present so the browser stores the cookie locally as well.
/// Also injects a lightweight session-exit hook into `index.html` so exiting a session returns to the dashboard.
pub fn inject_set_cookie_into_http_response(
    buf: &[u8],
    session_cookie: Option<&str>,
) -> Vec<u8> {
    if !buf.starts_with(b"HTTP/1.") {
        return buf.to_vec();
    }
    let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return buf.to_vec();
    };
    let header_bytes = &buf[..header_end];
    let Ok(header_str) = std::str::from_utf8(header_bytes) else {
        return buf.to_vec();
    };
    if header_str.starts_with("HTTP/1.1 101") || header_str.starts_with("HTTP/1.0 101") {
        return buf.to_vec();
    }

    let body_bytes = &buf[header_end + 4..];
    let mut rewritten_body: Option<Vec<u8>> = None;
    if let Ok(body_str) = std::str::from_utf8(body_bytes) {
        if body_str.contains("assets/app.js") && body_str.contains("</body>") {
            let new_body = if body_str.contains("<script type=\"module\" src=\"assets/app.js\"") {
                body_str.replacen(
                    "<script type=\"module\" src=\"assets/app.js\"",
                    &format!(
                        "{ZELLIJ_HTML_ASSETS_SNIPPET}        <script type=\"module\" src=\"assets/app.js\""
                    ),
                    1,
                )
            } else {
                body_str.replacen(
                    "</body>",
                    &format!("{ZELLIJ_HTML_ASSETS_SNIPPET}</body>"),
                    1,
                )
            };
            rewritten_body = Some(new_body.into_bytes());
        }
    }

    let lower = header_str.to_ascii_lowercase();
    let mut extra = String::new();
    if let Some(cookie_kv) = session_cookie {
        if !lower.contains("set-cookie: session_token=") {
            extra.push_str(&format!(
                "\r\nSet-Cookie: {cookie_kv}; Path=/; SameSite=Lax"
            ));
        }
    }
    if !lower.contains("\r\nconnection:") {
        extra.push_str("\r\nConnection: close");
    }
    if extra.is_empty() && rewritten_body.is_none() {
        return buf.to_vec();
    }

    let final_body = rewritten_body.as_deref().unwrap_or(body_bytes);
    let mut out_headers = String::with_capacity(header_str.len() + extra.len() + 64);
    for (idx, line) in header_str.split("\r\n").enumerate() {
        if idx > 0 {
            out_headers.push_str("\r\n");
        }
        if rewritten_body.is_some() {
            if let Some((k, _)) = line.split_once(':') {
                if k.trim().eq_ignore_ascii_case("content-length") {
                    out_headers.push_str(&format!("content-length: {}", final_body.len()));
                    continue;
                }
            }
        }
        out_headers.push_str(line);
    }
    out_headers.push_str(&extra);
    out_headers.push_str("\r\n\r\n");

    let mut out = out_headers.into_bytes();
    out.extend_from_slice(final_body);
    out
}

pub struct ZellijWebManager {
    web_port: u16,
    cached_session_cookie: Mutex<Option<String>>,
    start_lock: Mutex<()>,
}

impl ZellijWebManager {
    pub fn new(web_port: u16) -> Self {
        Self {
            web_port,
            cached_session_cookie: Mutex::new(None),
            start_lock: Mutex::new(()),
        }
    }

    pub fn web_port(&self) -> u16 {
        self.web_port
    }

    async fn is_port_listening(&self) -> bool {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.web_port));
        tokio::time::timeout(Duration::from_millis(200), TcpStream::connect(addr))
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false)
    }

    /// Ensures `127.0.0.1:<web_port>` is listening (spawning `zellij web` in an isolated
    /// `KillMode=process` user service unit if available, or falling back to direct spawn)
    /// and returns a valid `session_token=<val>` cookie if `zellij web` authentication is active.
    pub async fn ensure_running_and_get_cookie(&self) -> Result<Option<String>> {
        let _ = ensure_zellij_web_sharing_enabled();
        if !self.is_port_listening().await {
            let _guard = self.start_lock.lock().await;
            if !self.is_port_listening().await {
                tracing::info!(
                    "Starting local zellij web server on 127.0.0.1:{}",
                    self.web_port
                );
                // Prefer starting in a dedicated systemd --user unit with KillMode=process
                // so web-created Zellij session servers survive sshcast-relay restarts.
                let mut started_via_systemd = false;
                if self.web_port == 8082 {
                    if let Ok(st) = Command::new("systemctl")
                        .args(["--user", "start", "sshcast-zellij-web.service"])
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status()
                    {
                        started_via_systemd = st.success();
                    }
                }
                if !started_via_systemd {
                    let unit_name = format!("sshcast-zellij-web-{}", self.web_port);
                    if let Ok(st) = Command::new("systemd-run")
                        .args([
                            "--user",
                            &format!("--unit={unit_name}"),
                            "--setenv=TERM=xterm-256color",
                            "--property=KillMode=process",
                            "--property=Restart=on-failure",
                            "--collect",
                            "zellij",
                            "web",
                            "--ip",
                            "127.0.0.1",
                            "--port",
                            &self.web_port.to_string(),
                        ])
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status()
                    {
                        started_via_systemd = st.success();
                    }
                }

                if started_via_systemd {
                    for _ in 0..30 {
                        if self.is_port_listening().await {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }

                if !self.is_port_listening().await {
                    let _ = Command::new("zellij")
                        .env("TERM", "xterm-256color")
                        .args([
                            "web",
                            "--ip",
                            "127.0.0.1",
                            "--port",
                            &self.web_port.to_string(),
                        ])
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .context("failed to spawn `zellij web`")?;

                    for _ in 0..60 {
                        if self.is_port_listening().await {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        }

        {
            let guard = self.cached_session_cookie.lock().await;
            if guard.is_some() {
                return Ok(guard.clone());
            }
        }

        let _guard = self.start_lock.lock().await;
        {
            let guard = self.cached_session_cookie.lock().await;
            if guard.is_some() {
                return Ok(guard.clone());
            }
        }

        if let Some(cookie) = self.mint_session_cookie().await {
            let mut guard = self.cached_session_cookie.lock().await;
            *guard = Some(cookie.clone());
            return Ok(Some(cookie));
        }

        Ok(None)
    }

    async fn mint_session_cookie(&self) -> Option<String> {
        let out = Command::new("zellij")
            .args(["web", "--create-token"])
            .stdin(Stdio::null())
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let token = parse_zellij_create_token_output(&stdout)?;

        let body = format!("{{\"auth_token\":\"{token}\",\"remember_me\":true}}");
        let req = format!(
            "POST /command/login HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.web_port,
            body.len(),
            body
        );

        let addr = SocketAddr::from(([127, 0, 0, 1], self.web_port));
        let mut stream = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr))
            .await
            .ok()?
            .ok()?;
        stream.write_all(req.as_bytes()).await.ok()?;
        let mut resp_buf = Vec::with_capacity(1024);
        let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut resp_buf)).await;
        let resp_str = String::from_utf8_lossy(&resp_buf);

        for line in resp_str.lines() {
            if let Some((k, v)) = line.split_once(':') {
                if k.trim().eq_ignore_ascii_case("set-cookie") {
                    for part in v.split(';') {
                        let trimmed = part.trim();
                        if trimmed.starts_with("session_token=") {
                            tracing::info!("Acquired automatic zellij web session_token cookie");
                            return Some(trimmed.to_string());
                        }
                    }
                }
            }
        }
        None
    }
}

/// Discovers non-loopback local IPv4 addresses by probing UDP routing table + STUN reflexive address.
async fn gather_candidates_and_punch(
    stun_servers: &[String],
    local_tcp_port: u16,
    remote_udp_candidates: &[String],
) -> (Vec<String>, Vec<String>) {
    let mut tcp_candidates = Vec::new();
    let mut udp_candidates = Vec::new();

    // Probe local interface IP used for default route
    if let Ok(probe_sock) = UdpSocket::bind("0.0.0.0:0").await {
        if probe_sock.connect("1.1.1.1:80").await.is_ok() {
            if let Ok(local_addr) = probe_sock.local_addr() {
                if !local_addr.ip().is_loopback() && !local_addr.ip().is_unspecified() {
                    tcp_candidates.push(SocketAddr::new(local_addr.ip(), local_tcp_port).to_string());
                }
            }
        }
    }

    if let Ok(udp_sock) = UdpSocket::bind("0.0.0.0:0").await {
        if let Ok(local_udp) = udp_sock.local_addr() {
            for cand_str in tcp_candidates.iter() {
                if let Ok(sa) = cand_str.parse::<SocketAddr>() {
                    let u = SocketAddr::new(sa.ip(), local_udp.port()).to_string();
                    if !udp_candidates.contains(&u) {
                        udp_candidates.push(u);
                    }
                }
            }
        }

        // Send hole-punch packets to remote UDP candidates
        for remote in remote_udp_candidates {
            if let Ok(addr) = remote.parse::<SocketAddr>() {
                let _ = udp_sock.send_to(b"SC_P2P_PUNCH", addr).await;
            }
        }

        // Query first reachable STUN server with a short timeout
        let (stun_req, tx_id) = build_stun_binding_request();

        for stun_srv in stun_servers {
            let send_fut = udp_sock.send_to(&stun_req, stun_srv.as_str());
            if tokio::time::timeout(Duration::from_millis(250), send_fut)
                .await
                .is_ok()
            {
                let mut buf = [0u8; 512];
                if let Ok(Ok((n, _))) =
                    tokio::time::timeout(Duration::from_millis(350), udp_sock.recv_from(&mut buf))
                        .await
                {
                    if let Some(mapped) = parse_stun_binding_response(&buf[..n], &tx_id) {
                        let udp_s = mapped.to_string();
                        if !udp_candidates.contains(&udp_s) {
                            udp_candidates.push(udp_s);
                        }
                        let tcp_s = SocketAddr::new(mapped.ip(), local_tcp_port).to_string();
                        if !tcp_candidates.contains(&tcp_s) {
                            tcp_candidates.insert(0, tcp_s);
                        }
                        break;
                    }
                }
            }
        }
    }

    (tcp_candidates, udp_candidates)
}

async fn handle_direct_p2p_tcp_stream(
    mut p2p_stream: TcpStream,
    web_mgr: Arc<ZellijWebManager>,
    client_auth_token: [u8; 32],
    relay_auth_token: [u8; 32],
    cipher_key: [u8; 32],
) -> Result<()> {
    let mut c2r_cipher = P2pStreamCipher::new(cipher_key, b"c2r");
    let mut r2c_cipher = P2pStreamCipher::new(cipher_key, b"r2c");

    let mut auth_buf = [0u8; 32];
    tokio::time::timeout(Duration::from_secs(3), p2p_stream.read_exact(&mut auth_buf))
        .await
        .context("P2P stream handshake timed out")??;
    c2r_cipher.apply_keystream(&mut auth_buf);
    if auth_buf != client_auth_token {
        anyhow::bail!("invalid P2P client auth token");
    }

    let mut reply_auth = relay_auth_token;
    r2c_cipher.apply_keystream(&mut reply_auth);
    p2p_stream.write_all(&reply_auth).await?;

    // Read the first chunk of request data; if EOF (0 bytes), this was a P2P reachability probe.
    let mut first_buf = vec![0u8; 16384];
    let first_n = match p2p_stream.read(&mut first_buf).await {
        Ok(0) | Err(_) => return Ok(()),
        Ok(n) => n,
    };
    c2r_cipher.apply_keystream(&mut first_buf[..first_n]);

    if let Some(mut static_resp) = try_build_sshcast_asset_http_response(&first_buf[..first_n]) {
        r2c_cipher.apply_keystream(&mut static_resp);
        p2p_stream.write_all(&static_resp).await?;
        let _ = p2p_stream.shutdown().await;
        return Ok(());
    }

    let session_cookie = web_mgr.ensure_running_and_get_cookie().await?;
    let local_addr = SocketAddr::from(([127, 0, 0, 1], web_mgr.web_port()));
    let zellij_stream = TcpStream::connect(local_addr)
        .await
        .with_context(|| format!("failed to connect to local zellij web at {local_addr}"))?;

    let (mut p2p_rd, mut p2p_wr) = p2p_stream.into_split();
    let (mut z_rd, mut z_wr) = zellij_stream.into_split();

    let web_port = web_mgr.web_port();
    let rewritten_first = rewrite_http_request_for_zellij_web(
        &first_buf[..first_n],
        web_port,
        session_cookie.as_deref(),
    );
    z_wr.write_all(&rewritten_first).await?;

    let mut c2r_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            let n = match p2p_rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let chunk = &mut buf[..n];
            c2r_cipher.apply_keystream(chunk);
            if z_wr.write_all(chunk).await.is_err() {
                break;
            }
        }
        let _ = z_wr.shutdown().await;
    });

    let cookie_for_resp = session_cookie;
    let r2c_task = tokio::spawn(async move {
        let mut first_chunk = true;
        let mut is_ws = false;
        let mut buf = vec![0u8; 16384];
        loop {
            let n = match z_rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let mut out_bytes = if first_chunk {
                first_chunk = false;
                if buf[..n].starts_with(b"HTTP/1.1 101") || buf[..n].starts_with(b"HTTP/1.0 101") {
                    is_ws = true;
                }
                inject_set_cookie_into_http_response(&buf[..n], cookie_for_resp.as_deref())
            } else {
                buf[..n].to_vec()
            };
            if is_ws {
                rewrite_websocket_normal_close_to_4001(&mut out_bytes);
            }
            r2c_cipher.apply_keystream(&mut out_bytes);
            if p2p_wr.write_all(&out_bytes).await.is_err() {
                break;
            }
        }
        let _ = p2p_wr.shutdown().await;
    });

    let _ = r2c_task.await;
    let _ = tokio::time::timeout(Duration::from_millis(150), &mut c2r_task).await;
    c2r_task.abort();
    Ok(())
}

async fn handle_incoming_zellij_frame(
    frame: ZellijTunnelFrame,
    cfg: Arc<RelayConfig>,
    web_mgr: Arc<ZellijWebManager>,
    active_tunnels: Arc<Mutex<HashMap<String, mpsc::Sender<Option<Vec<u8>>>>>>,
    outbound_tx: mpsc::Sender<RelayStreamMessage>,
) {
    match ZellijFrameType::try_from(frame.frame_type).unwrap_or(ZellijFrameType::Unspecified) {
        ZellijFrameType::P2pOffer => {
            tokio::spawn(async move {
                if let Err(e) = verify_zellij_tunnel_frame(
                    &frame,
                    NodeRole::Client,
                    &cfg.grant.user_pubkey,
                    now_unix_sec(),
                ) {
                    tracing::warn!("Rejected P2P_OFFER with invalid signature: {}", e);
                    return;
                }

                let Some(offer) = P2pEndpointHandshake::from_bytes(&frame.payload) else {
                    tracing::warn!("Invalid P2P_OFFER JSON");
                    return;
                };

                let listener = match TcpListener::bind("0.0.0.0:0").await {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::warn!("Failed to bind P2P TCP listener: {}", e);
                        return;
                    }
                };
                let local_port = match listener.local_addr() {
                    Ok(a) => a.port(),
                    Err(_) => return,
                };

                let (tcp_candidates, udp_candidates) = gather_candidates_and_punch(
                    &cfg.stun_servers,
                    local_port,
                    &offer.udp_candidates,
                )
                .await;

                let answer = P2pEndpointHandshake::new(tcp_candidates, udp_candidates);
                let answer_bytes = answer.to_bytes();

                let mut reply_frame = ZellijTunnelFrame {
                    tunnel_id: frame.tunnel_id.clone(),
                    relay_node_id: cfg.grant.node_id.clone(),
                    client_node_id: frame.client_node_id.clone(),
                    frame_type: ZellijFrameType::P2pAnswer as i32,
                    payload: answer_bytes,
                    error_message: String::new(),
                    sender_grant: Some(cfg.grant.clone()),
                    sender_signature: Vec::new(),
                };
                let _ = sign_zellij_tunnel_frame(&mut reply_frame, &cfg.node_signing_key);

                let (client_auth_token, relay_auth_token, cipher_key) = derive_p2p_session_keys(
                    &frame.tunnel_id,
                    &offer,
                    &frame.sender_signature,
                    &answer,
                    &reply_frame.sender_signature,
                );

                let _ = outbound_tx
                    .send(RelayStreamMessage {
                        payload: Some(RelayOutPayload::ZellijFrame(reply_frame)),
                    })
                    .await;

                loop {
                    match tokio::time::timeout(Duration::from_secs(3600), listener.accept()).await {
                        Ok(Ok((stream, peer_addr))) => {
                            tracing::debug!("Accepted direct P2P Zellij stream from {}", peer_addr);
                            let mgr = Arc::clone(&web_mgr);
                            tokio::spawn(async move {
                                let _ = handle_direct_p2p_tcp_stream(
                                    stream,
                                    mgr,
                                    client_auth_token,
                                    relay_auth_token,
                                    cipher_key,
                                )
                                .await;
                            });
                        }
                        _ => break,
                    }
                }
            });
        }
        ZellijFrameType::Open => {
            if let Err(e) = verify_zellij_tunnel_frame(
                &frame,
                NodeRole::Client,
                &cfg.grant.user_pubkey,
                now_unix_sec(),
            ) {
                tracing::warn!("Rejected Zellij OPEN frame with invalid signature: {}", e);
                return;
            }

            let tunnel_id = frame.tunnel_id.clone();
            let client_node_id = frame.client_node_id.clone();
            let relay_node_id = cfg.grant.node_id.clone();

            // Synchronously register the tunnel channel BEFORE spawning so subsequent DATA/CLOSE
            // frames on the gRPC stream are guaranteed to find this tunnel in strict FIFO order.
            let (in_tx, mut in_rx) = mpsc::channel::<Option<Vec<u8>>>(1024);
            if !frame.payload.is_empty() {
                let _ = in_tx.try_send(Some(frame.payload));
            }
            active_tunnels
                .lock()
                .await
                .insert(tunnel_id.clone(), in_tx);

            tokio::spawn(async move {
                let Some(Some(first_req_chunk)) = in_rx.recv().await else {
                    active_tunnels.lock().await.remove(&tunnel_id);
                    return;
                };

                if let Some(static_resp) = try_build_sshcast_asset_http_response(&first_req_chunk)
                {
                    for chunk in static_resp.chunks(16384) {
                        if outbound_tx
                            .send(RelayStreamMessage {
                                payload: Some(RelayOutPayload::ZellijFrame(ZellijTunnelFrame {
                                    tunnel_id: tunnel_id.clone(),
                                    relay_node_id: relay_node_id.clone(),
                                    client_node_id: client_node_id.clone(),
                                    frame_type: ZellijFrameType::Data as i32,
                                    payload: chunk.to_vec(),
                                    error_message: String::new(),
                                    sender_grant: None,
                                    sender_signature: Vec::new(),
                                })),
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    active_tunnels.lock().await.remove(&tunnel_id);
                    let _ = outbound_tx
                        .send(RelayStreamMessage {
                            payload: Some(RelayOutPayload::ZellijFrame(ZellijTunnelFrame {
                                tunnel_id,
                                relay_node_id,
                                client_node_id,
                                frame_type: ZellijFrameType::Close as i32,
                                payload: Vec::new(),
                                error_message: String::new(),
                                sender_grant: None,
                                sender_signature: Vec::new(),
                            })),
                        })
                        .await;
                    return;
                }

                let session_cookie = match web_mgr.ensure_running_and_get_cookie().await {
                    Ok(c) => c,
                    Err(e) => {
                        active_tunnels.lock().await.remove(&tunnel_id);
                        let _ = outbound_tx
                            .send(RelayStreamMessage {
                                payload: Some(RelayOutPayload::ZellijFrame(ZellijTunnelFrame {
                                    tunnel_id,
                                    relay_node_id,
                                    client_node_id,
                                    frame_type: ZellijFrameType::Close as i32,
                                    payload: Vec::new(),
                                    error_message: format!("failed to start zellij web: {e}"),
                                    sender_grant: None,
                                    sender_signature: Vec::new(),
                                })),
                            })
                            .await;
                        return;
                    }
                };

                let addr = SocketAddr::from(([127, 0, 0, 1], web_mgr.web_port()));
                let tcp_stream = match TcpStream::connect(addr).await {
                    Ok(s) => s,
                    Err(e) => {
                        active_tunnels.lock().await.remove(&tunnel_id);
                        let _ = outbound_tx
                            .send(RelayStreamMessage {
                                payload: Some(RelayOutPayload::ZellijFrame(ZellijTunnelFrame {
                                    tunnel_id,
                                    relay_node_id,
                                    client_node_id,
                                    frame_type: ZellijFrameType::Close as i32,
                                    payload: Vec::new(),
                                    error_message: format!(
                                        "failed to connect to zellij web on {addr}: {e}"
                                    ),
                                    sender_grant: None,
                                    sender_signature: Vec::new(),
                                })),
                            })
                            .await;
                        return;
                    }
                };

                let (mut z_rd, mut z_wr) = tcp_stream.into_split();
                let web_port = web_mgr.web_port();
                let cookie_for_req = session_cookie.clone();
                tokio::spawn(async move {
                    let first_rewritten = rewrite_http_request_for_zellij_web(
                        &first_req_chunk,
                        web_port,
                        cookie_for_req.as_deref(),
                    );
                    if z_wr.write_all(&first_rewritten).await.is_ok() {
                        while let Some(item) = in_rx.recv().await {
                            let Some(chunk) = item else {
                                break;
                            };
                            if z_wr.write_all(&chunk).await.is_err() {
                                break;
                            }
                        }
                    }
                    let _ = z_wr.shutdown().await;
                });

                let cookie_for_resp = session_cookie;
                let mut first = true;
                let mut is_ws = false;
                let mut buf = vec![0u8; 16384];
                loop {
                    match z_rd.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let mut payload = if first {
                                first = false;
                                if buf[..n].starts_with(b"HTTP/1.1 101")
                                    || buf[..n].starts_with(b"HTTP/1.0 101")
                                {
                                    is_ws = true;
                                }
                                inject_set_cookie_into_http_response(
                                    &buf[..n],
                                    cookie_for_resp.as_deref(),
                                )
                            } else {
                                buf[..n].to_vec()
                            };
                            if is_ws {
                                rewrite_websocket_normal_close_to_4001(&mut payload);
                            }
                            if outbound_tx
                                .send(RelayStreamMessage {
                                    payload: Some(RelayOutPayload::ZellijFrame(
                                        ZellijTunnelFrame {
                                            tunnel_id: tunnel_id.clone(),
                                            relay_node_id: relay_node_id.clone(),
                                            client_node_id: client_node_id.clone(),
                                            frame_type: ZellijFrameType::Data as i32,
                                            payload,
                                            error_message: String::new(),
                                            sender_grant: None,
                                            sender_signature: Vec::new(),
                                        },
                                    )),
                                })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                }
                active_tunnels.lock().await.remove(&tunnel_id);
                let _ = outbound_tx
                    .send(RelayStreamMessage {
                        payload: Some(RelayOutPayload::ZellijFrame(ZellijTunnelFrame {
                            tunnel_id,
                            relay_node_id,
                            client_node_id,
                            frame_type: ZellijFrameType::Close as i32,
                            payload: Vec::new(),
                            error_message: String::new(),
                            sender_grant: None,
                            sender_signature: Vec::new(),
                        })),
                    })
                    .await;
            });
        }
        ZellijFrameType::Data => {
            let tx_opt = active_tunnels.lock().await.get(&frame.tunnel_id).cloned();
            if let Some(tx) = tx_opt {
                let _ = tx.send(Some(frame.payload)).await;
            }
        }
        ZellijFrameType::Close => {
            let tx_opt = active_tunnels.lock().await.remove(&frame.tunnel_id);
            if let Some(tx) = tx_opt {
                let _ = tx.send(None).await;
            }
        }
        _ => {}
    }
}

async fn discover_zellij_sessions_async() -> Vec<ZellijSessionInfo> {
    match tokio::time::timeout(
        Duration::from_secs(2),
        tokio::task::spawn_blocking(discover_zellij_sessions),
    )
    .await
    {
        Ok(Ok(sessions)) => sessions,
        _ => Vec::new(),
    }
}

async fn run_single_coordinator_relay_stream(
    server_url: &str,
    cfg: Arc<RelayConfig>,
    web_mgr: Arc<ZellijWebManager>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let mut endpoint = Endpoint::from_shared(server_url.to_string())
        .with_context(|| format!("invalid server URL {server_url}"))?
        .connect_timeout(Duration::from_millis(cfg.connect_timeout_ms))
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .http2_keep_alive_interval(Duration::from_secs(25))
        .keep_alive_timeout(Duration::from_secs(10));

    if server_url.trim().starts_with("https://") {
        endpoint = endpoint
            .tls_config(ClientTlsConfig::new().with_enabled_roots())
            .with_context(|| format!("failed to configure TLS for {server_url}"))?;
    }

    let channel = endpoint.connect().await?;
    let mut grpc_client = SshcastServiceClient::new(channel);

    let (out_tx, out_rx) = mpsc::channel::<RelayStreamMessage>(1024);

    let auth = create_node_auth(
        cfg.grant.clone(),
        &cfg.node_signing_key,
        now_unix_ms(),
    )?;
    out_tx
        .send(RelayStreamMessage {
            payload: Some(RelayOutPayload::AuthHandshake(auth)),
        })
        .await?;

    let initial_sessions = discover_zellij_sessions_async().await;
    out_tx
        .send(RelayStreamMessage {
            payload: Some(RelayOutPayload::ZellijStatus(RelayZellijStatus {
                node_id: cfg.grant.node_id.clone(),
                zellij_enabled: true,
                sessions: initial_sessions.clone(),
                updated_at_unix_ms: now_unix_ms(),
            })),
        })
        .await?;

    let response = grpc_client
        .connect_relay(ReceiverStream::new(out_rx))
        .await?;
    let mut inbound = response.into_inner();
    tracing::info!(
        "Connected Zellij relay stream to {} (node_id={}, sessions={})",
        server_url,
        cfg.grant.node_id,
        initial_sessions.len()
    );

    let active_tunnels: Arc<Mutex<HashMap<String, mpsc::Sender<Option<Vec<u8>>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let mut last_sessions = initial_sessions;
    let mut status_ticker = tokio::time::interval(Duration::from_secs(10));
    status_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    return Ok(());
                }
            }
            _ = status_ticker.tick() => {
                let current = discover_zellij_sessions_async().await;
                if current != last_sessions {
                    last_sessions = current.clone();
                    let _ = out_tx.send(RelayStreamMessage {
                        payload: Some(RelayOutPayload::ZellijStatus(RelayZellijStatus {
                            node_id: cfg.grant.node_id.clone(),
                            zellij_enabled: true,
                            sessions: current,
                            updated_at_unix_ms: now_unix_ms(),
                        })),
                    }).await;
                }
            }
            msg_res = inbound.message() => {
                let Some(msg) = msg_res? else {
                    anyhow::bail!("coordinator closed ConnectRelay stream");
                };
                match msg.payload {
                    Some(ServerInPayload::ServerHeartbeatEpochMs(_)) => {}
                    Some(ServerInPayload::RefreshSessions(true)) => {
                        let current = discover_zellij_sessions_async().await;
                        last_sessions = current.clone();
                        let _ = out_tx.send(RelayStreamMessage {
                            payload: Some(RelayOutPayload::ZellijStatus(RelayZellijStatus {
                                node_id: cfg.grant.node_id.clone(),
                                zellij_enabled: true,
                                sessions: current,
                                updated_at_unix_ms: now_unix_ms(),
                            })),
                        }).await;
                    }
                    Some(ServerInPayload::ZellijFrame(frame)) => {
                        handle_incoming_zellij_frame(
                            frame,
                            Arc::clone(&cfg),
                            Arc::clone(&web_mgr),
                            Arc::clone(&active_tunnels),
                            out_tx.clone(),
                        )
                        .await;
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Runs the persistent outbound `ConnectRelay` stream loop when `cfg.zellij_enabled` is `true`.
pub async fn run_zellij_relay_worker(
    cfg: RelayConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    if !cfg.zellij_enabled || cfg.servers.is_empty() {
        return;
    }
    let cfg = Arc::new(cfg);
    let web_mgr = Arc::new(ZellijWebManager::new(cfg.zellij_web_port));
    let mut server_idx = 0usize;

    loop {
        if *shutdown_rx.borrow() {
            return;
        }
        let server_url = &cfg.servers[server_idx % cfg.servers.len()];
        server_idx = server_idx.wrapping_add(1);

        if let Err(e) = run_single_coordinator_relay_stream(
            server_url,
            Arc::clone(&cfg),
            Arc::clone(&web_mgr),
            shutdown_rx.clone(),
        )
        .await
        {
            tracing::warn!(
                "Zellij ConnectRelay stream to {} ended ({}); reconnecting in 2s",
                server_url,
                e
            );
        }

        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    return;
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
        }
    }
}
