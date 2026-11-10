use crate::cli::Verbosity;
use crate::scanner::HostResult;
use crate::vendor;

pub fn render_text(results: &[HostResult], verbosity: Verbosity) -> String {
    let mut output = String::new();
    for result in results {
        let state = if result.reachable {
            "alive"
        } else {
            "unreachable"
        };
        output.push_str(&format!("{}\t{}\n", result.address, state));
        if let Some(hostname) = &result.hostname {
            output.push_str(&format!("  hostname\t{hostname}\n"));
        }
        if let Some(mac_address) = &result.mac_address {
            output.push_str(&format!("  mac\t{mac_address}\n"));
        }
        if verbosity != Verbosity::HostsOnly {
            for service in &result.services {
                output.push_str(&format!("  {}\t{}", service.port, service.name));
                if let Some(banner) = &service.banner {
                    output.push_str(&format!("\t{banner}"));
                }
                output.push('\n');
            }
            if let Some(http) = &result.http {
                if let Some(title) = &http.title {
                    output.push_str(&format!("  http-title\t{title}\n"));
                }
                if let Some(server) = &http.server {
                    output.push_str(&format!("  http-server\t{server}\n"));
                }
            }
            for user in &result.users {
                output.push_str(&format!("  user\t{user}\n"));
            }
            for share in &result.shares {
                output.push_str(&format!("  share\t{}\t{}\n", share.kind, share.name));
            }
            if let Some(remote_time) = &result.remote_time {
                output.push_str(&format!("  remote-time\t{remote_time}\n"));
            }
        }
    }
    output
}

pub fn render_xml(results: &[HostResult]) -> String {
    let mut output = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<scan>\n");
    for result in results {
        output.push_str(&format!(
            "  <host address=\"{}\" reachable=\"{}\"",
            result.address, result.reachable
        ));
        if let Some(hostname) = &result.hostname {
            output.push_str(&format!(" hostname=\"{}\"", escape_xml(hostname)));
        }
        if let Some(mac_address) = &result.mac_address {
            output.push_str(&format!(" mac=\"{}\"", escape_xml(mac_address)));
        }
        output.push_str(">\n");
        for service in &result.services {
            output.push_str(&format!(
                "    <service port=\"{}\" name=\"{}\"",
                service.port,
                escape_xml(&service.name)
            ));
            if let Some(banner) = &service.banner {
                output.push_str(&format!(" banner=\"{}\"", escape_xml(banner)));
            }
            output.push_str(" />\n");
        }
        for user in &result.users {
            output.push_str(&format!("    <user name=\"{}\" />\n", escape_xml(user)));
        }
        for share in &result.shares {
            output.push_str(&format!(
                "    <share name=\"{}\" kind=\"{}\" />\n",
                escape_xml(&share.name),
                escape_xml(share.kind)
            ));
        }
        if let Some(remote_time) = &result.remote_time {
            output.push_str(&format!(
                "    <remote-time value=\"{}\" />\n",
                escape_xml(remote_time)
            ));
        }
        if let Some(http) = &result.http {
            output.push_str(&format!("    <http port=\"{}\"", http.port));
            if let Some(status) = http.status {
                output.push_str(&format!(" status=\"{status}\""));
            }
            if let Some(title) = &http.title {
                output.push_str(&format!(" title=\"{}\"", escape_xml(title)));
            }
            if let Some(server) = &http.server {
                output.push_str(&format!(" server=\"{}\"", escape_xml(server)));
            }
            output.push_str(" />\n");
        }
        output.push_str("  </host>\n");
    }
    output.push_str("</scan>\n");
    output
}

/// CSV with `;` separator and UTF-8 BOM so spreadsheet apps open it directly.
pub fn render_csv(results: &[HostResult]) -> String {
    let mut output = String::from(
        "\u{feff}IP;Nombre;MAC;Fabricante;Puertos;Servicios;Web;Usuarios;Recursos;Hora\r\n",
    );
    for result in results {
        let row = [
            result.address.to_string(),
            result.hostname.clone().unwrap_or_default(),
            result.mac_address.clone().unwrap_or_default(),
            vendor_text(result),
            result
                .services
                .iter()
                .map(|service| service.port.to_string())
                .collect::<Vec<_>>()
                .join(" "),
            services_text(result),
            web_text(result),
            result.users.join(", "),
            shares_text(result),
            result.remote_time.clone().unwrap_or_default(),
        ];
        let line = row.iter().map(|field| csv_field(field)).collect::<Vec<_>>();
        output.push_str(&line.join(";"));
        output.push_str("\r\n");
    }
    output
}

/// Self-contained HTML report.
pub fn render_html(results: &[HostResult]) -> String {
    let mut rows = String::new();
    for result in results {
        let services = result
            .services
            .iter()
            .map(|service| {
                format!(
                    "<span class=\"chip\"><b>{}</b> {}</span>",
                    service.port,
                    escape_xml(&service.name)
                )
            })
            .collect::<String>();
        let mut details = Vec::new();
        let web = web_text(result);
        if !web.is_empty() {
            details.push(format!("Web: {}", escape_xml(&web)));
        }
        if !result.users.is_empty() {
            details.push(format!(
                "Usuarios: {}",
                escape_xml(&result.users.join(", "))
            ));
        }
        if !result.shares.is_empty() {
            details.push(format!("Recursos: {}", escape_xml(&shares_text(result))));
        }
        if let Some(time) = &result.remote_time {
            details.push(format!("Hora: {}", escape_xml(time)));
        }
        rows.push_str(&format!(
            "<tr><td class=\"ip\">{}</td><td>{}</td><td>{}</td><td class=\"mono\">{}</td><td>{}</td><td class=\"muted\">{}</td></tr>\n",
            result.address,
            escape_xml(result.hostname.as_deref().unwrap_or("")),
            services,
            escape_xml(result.mac_address.as_deref().unwrap_or("")),
            escape_xml(&vendor_text(result)),
            details.join("<br>"),
        ));
    }
    format!(
        r#"<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>scanner-rs · resultados</title>
<style>
body {{ margin: 0; padding: 32px; background: #f8f9fb; color: #111827; font: 14px/1.5 "Segoe UI", system-ui, sans-serif; }}
h1 {{ font-size: 20px; margin: 0 0 4px; }}
p {{ color: #6b7280; margin: 0 0 20px; }}
table {{ width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #e2e6ec; }}
th {{ text-align: left; font-weight: 600; font-size: 12px; color: #6b7280; padding: 10px 14px; border-bottom: 1px solid #e2e6ec; }}
td {{ padding: 10px 14px; border-bottom: 1px solid #f0f2f5; vertical-align: top; }}
.ip {{ font-weight: 600; white-space: nowrap; }}
.mono {{ font-family: Consolas, monospace; white-space: nowrap; }}
.muted {{ color: #6b7280; font-size: 13px; }}
.chip {{ display: inline-block; background: #e8f0fe; color: #2563eb; border-radius: 10px; padding: 1px 8px; margin: 1px 4px 1px 0; font-size: 13px; }}
</style>
</head>
<body>
<h1>scanner-rs</h1>
<p>{} equipos</p>
<table>
<thead><tr><th>IP</th><th>Nombre</th><th>Servicios</th><th>MAC</th><th>Fabricante</th><th>Detalles</th></tr></thead>
<tbody>
{}</tbody>
</table>
</body>
</html>
"#,
        results.len(),
        rows
    )
}

fn vendor_text(result: &HostResult) -> String {
    result
        .mac_address
        .as_deref()
        .and_then(vendor::lookup)
        .unwrap_or_default()
        .to_owned()
}

fn services_text(result: &HostResult) -> String {
    result
        .services
        .iter()
        .map(|service| format!("{} {}", service.port, service.name))
        .collect::<Vec<_>>()
        .join(", ")
}

fn shares_text(result: &HostResult) -> String {
    result
        .shares
        .iter()
        .map(|share| share.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

fn web_text(result: &HostResult) -> String {
    result
        .http
        .as_ref()
        .map(|http| {
            [http.title.as_deref(), http.server.as_deref()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" · ")
        })
        .unwrap_or_default()
}

fn csv_field(value: &str) -> String {
    let value = value.replace(['\r', '\n'], " ");
    if value.contains([';', '"', ',']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value
    }
}

fn escape_xml(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character == '\t'
                || character == '\n'
                || character == '\r'
                || !character.is_control()
            {
                character
            } else {
                '\u{fffd}'
            }
        })
        .collect::<String>()
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::{render_csv, render_html, render_xml};
    use crate::scanner::{HostResult, HttpMetadata, ServiceRecord};
    use std::net::Ipv4Addr;

    #[test]
    fn xml_output_escapes_discovered_text() {
        let results = [HostResult {
            address: Ipv4Addr::LOCALHOST,
            reachable: true,
            mac_address: None,
            hostname: Some("localhost".to_owned()),
            services: vec![ServiceRecord {
                port: 80,
                name: "http".to_owned(),
                banner: Some("a&b\0control".to_owned()),
            }],
            http: Some(HttpMetadata {
                port: 80,
                status: Some(200),
                title: Some("<demo>".to_owned()),
                server: None,
                authenticate: None,
            }),
            users: vec!["LAB\\alice".to_owned()],
            shares: vec![crate::platform::ShareInfo {
                name: "public".to_owned(),
                kind: "disk",
            }],
            remote_time: Some("2026-11-10 12:00:00".to_owned()),
        }];

        let xml = render_xml(&results);
        assert!(xml.contains("banner=\"a&amp;b�control\""));
        assert!(!xml.contains('\0'));
        assert!(xml.contains("title=\"&lt;demo&gt;\""));
        assert!(xml.contains("hostname=\"localhost\""));
        assert!(xml.contains("<share name=\"public\" kind=\"disk\" />"));
    }

    #[test]
    fn csv_and_html_include_ports_and_escape_text() {
        let results = [HostResult {
            address: Ipv4Addr::new(192, 168, 1, 5),
            reachable: true,
            mac_address: Some("AA:BB:CC:DD:EE:FF".to_owned()),
            hostname: Some("pc;\"uno\"".to_owned()),
            services: vec![
                ServiceRecord {
                    port: 80,
                    name: "http".to_owned(),
                    banner: None,
                },
                ServiceRecord {
                    port: 445,
                    name: "microsoft-ds".to_owned(),
                    banner: None,
                },
            ],
            http: None,
            users: Vec::new(),
            shares: Vec::new(),
            remote_time: None,
        }];

        let csv = render_csv(&results);
        assert!(csv.starts_with('\u{feff}'));
        assert!(
            csv.contains("192.168.1.5;\"pc;\"\"uno\"\"\";AA:BB:CC:DD:EE:FF;MAC aleatoria;80 445;")
        );

        let html = render_html(&results);
        assert!(html.contains("<b>445</b> microsoft-ds"));
        assert!(html.contains("pc;&quot;uno&quot;"));
    }
}
