#![deny(warnings)]
use log::info;
use nat_common::{Chain, IpVersion, NftCell, ParseError, Protocol, TomlConfig};
use std::fmt::Display;
use std::fs;
use std::io;

/// 运行时Cell，包装NftCell和Comment
/// Comment仅用于运行时表示，不进入TOML配置
#[derive(Debug)]
pub enum RuntimeCell {
    Rule(NftCell),
    Comment(String),
}

impl Display for RuntimeCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuntimeCell::Rule(cell) => write!(f, "{}", cell),
            RuntimeCell::Comment(content) => write!(f, "{}", content),
        }
    }
}

/// 解析一行legacy配置，返回RuntimeCell或错误
/// 注释行返回 Some(RuntimeCell::Comment)
/// 空行返回 None
/// 规则行返回 Some(RuntimeCell::Rule)
fn parse_legacy_line(line: &str) -> Option<RuntimeCell> {
    let line = line.trim();

    // 处理注释
    if line.starts_with('#') {
        return Some(RuntimeCell::Comment(line.to_string()));
    }

    // 使用 nat-common 的 TryFrom 解析（包括NAT规则和Drop规则）
    match NftCell::try_from(line) {
        Ok(cell) => Some(RuntimeCell::Rule(cell)),
        Err(ParseError::Skip) => None,
        Err(ParseError::InvalidFormat(msg)) => {
            log::warn!("跳过无效配置行: {}", msg);
            None
        }
    }
}

pub(crate) fn example(conf: &str) {
    info!("请在 {} 编写转发规则，内容类似：", &conf);
    info!(
        "{}",
        "SINGLE,10000,443,baidu.com,all,ipv4\n\
                    RANGE,1000,2000,baidu.com,tcp,ipv6\n\
                    RANGE,53051,53080,51051,123.123.123.123,all,ipv4\n\
                    REDIRECT,8000,3128,all,ipv4\n\
                    REDIRECT,8000-9000,3128,tcp,all\n\
                    DROP,input,src_ip=180.213.132.211,all,ipv4\n\
                    DROP,input,src_ip=240e:328:1301::/48,all,ipv6\n\
                    DROP,forward,dst_port=22,tcp,all\n\
                    # 格式: TYPE,port(s),port/domain,protocol,ip_version\n\
                    # TYPE: SINGLE, RANGE, REDIRECT 或 DROP\n\
                    # RANGE格式: RANGE,start,end,domain 或 RANGE,start,end,dport,domain\n\
                    # REDIRECT格式: REDIRECT,src_port,dst_port 或 REDIRECT,src_port-src_port_end,dst_port\n\
                    # DROP格式: DROP,chain,key=value,...,protocol,ip_version\n\
                    #   chain: input 或 forward\n\
                    #   key=value: src_ip=IP, dst_ip=IP, src_port=PORT, dst_port=PORT\n\
                    # protocol: tcp, udp, all\n\
                    # ip_version: ipv4, ipv6, all"
    )
}

pub fn read_config(conf: &str) -> Result<Vec<RuntimeCell>, io::Error> {
    let mut cells = vec![];
    let mut contents = fs::read_to_string(conf)?;
    contents = contents.replace("\r\n", "\n");

    for line in contents.lines() {
        if let Some(cell) = parse_legacy_line(line) {
            cells.push(cell);
        }
    }
    Ok(cells)
}

// 读取TOML配置文件
pub fn read_toml_config(toml_path: &str) -> Result<Vec<RuntimeCell>, io::Error> {
    let contents = fs::read_to_string(toml_path)?;

    // 使用 nat-common 的解析和验证
    let config = TomlConfig::from_toml_str(&contents)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut cells = Vec::new();

    // 处理所有规则（包括NAT和Filter）
    for rule in config.rules {
        // 如果有注释，先添加注释
        let comment = match &rule {
            NftCell::Single { comment, .. } => comment.clone(),
            NftCell::Range { comment, .. } => comment.clone(),
            NftCell::Redirect { comment, .. } => comment.clone(),
            NftCell::Drop { comment, .. } => comment.clone(),
        };

        if let Some(comment_text) = comment {
            cells.push(RuntimeCell::Comment(format!("# {comment_text}")));
        }

        cells.push(RuntimeCell::Rule(rule));
    }

    Ok(cells)
}

// TOML配置示例函数
pub fn toml_example(conf: &str) -> Result<(), io::Error> {
    let example_config = TomlConfig {
        rules: vec![
            NftCell::Single {
                sport: 10000,
                dport: 443,
                domain: "baidu.com".to_string(),
                protocol: Protocol::All,
                ip_version: IpVersion::V4,
                comment: Some("百度HTTPS服务转发示例".to_string()),
            },
            NftCell::Range {
                port_start: 1000,
                port_end: 2000,
                dport: None,
                domain: "baidu.com".to_string(),
                protocol: Protocol::Tcp,
                ip_version: IpVersion::V4,
                comment: Some("端口范围转发示例".to_string()),
            },
            NftCell::Range {
                port_start: 53051,
                port_end: 53080,
                dport: Some(51051),
                domain: "123.123.123.123".to_string(),
                protocol: Protocol::All,
                ip_version: IpVersion::V4,
                comment: Some("端口段平移转发示例".to_string()),
            },
            NftCell::Redirect {
                src_port: 8000,
                src_port_end: None,
                dst_port: 3128,
                protocol: Protocol::All,
                ip_version: IpVersion::V4,
                comment: Some("单端口重定向到本机示例".to_string()),
            },
            NftCell::Redirect {
                src_port: 30001,
                src_port_end: Some(39999),
                dst_port: 45678,
                protocol: Protocol::Tcp,
                ip_version: IpVersion::V4,
                comment: Some("端口范围重定向到本机示例".to_string()),
            },
            NftCell::Drop {
                chain: Chain::Input,
                src_ip: Some("180.213.132.211".to_string()),
                dst_ip: None,
                src_port: None,
                src_port_end: None,
                dst_port: None,
                dst_port_end: None,
                protocol: Protocol::All,
                comment: Some("阻止特定IPv4地址".to_string()),
            },
            NftCell::Drop {
                chain: Chain::Input,
                src_ip: Some("240e:328:1301::/48".to_string()),
                dst_ip: None,
                src_port: None,
                src_port_end: None,
                dst_port: None,
                dst_port_end: None,
                protocol: Protocol::All,
                comment: Some("阻止IPv6网段".to_string()),
            },
            NftCell::Drop {
                chain: Chain::Input,
                src_ip: None,
                dst_ip: None,
                src_port: None,
                src_port_end: None,
                dst_port: Some(22),
                dst_port_end: None,
                protocol: Protocol::Tcp,
                comment: Some("阻止SSH端口访问".to_string()),
            },
        ],
    };

    let toml_str = example_config
        .to_toml_string()
        .map_err(|e| io::Error::other(format!("序列化TOML失败: {e}")))?;

    info!("请在 {} 编写转发规则，内容类似：\n {toml_str}", &conf);

    Ok(())
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod redirect_parse_tests {
    use super::*;

    #[test]
    fn test_parse_redirect_single_port() {
        let line = "REDIRECT,8000,3128";
        let result = parse_legacy_line(line);
        assert!(result.is_some());
        match result.unwrap() {
            RuntimeCell::Rule(NftCell::Redirect {
                src_port,
                src_port_end,
                dst_port,
                ..
            }) => {
                assert_eq!(src_port, 8000);
                assert_eq!(src_port_end, None);
                assert_eq!(dst_port, 3128);
            }
            other => panic!("Expected Redirect variant, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_redirect_port_range() {
        let line = "REDIRECT,30001-39999,45678";
        let result = parse_legacy_line(line);
        assert!(result.is_some());
        match result.unwrap() {
            RuntimeCell::Rule(NftCell::Redirect {
                src_port,
                src_port_end,
                dst_port,
                ..
            }) => {
                assert_eq!(src_port, 30001);
                assert_eq!(src_port_end, Some(39999));
                assert_eq!(dst_port, 45678);
            }
            other => panic!("Expected Redirect variant, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_redirect_with_protocol() {
        let line = "REDIRECT,9000,8080,tcp";
        let result = parse_legacy_line(line);
        assert!(result.is_some());
        match result.unwrap() {
            RuntimeCell::Rule(NftCell::Redirect {
                src_port, dst_port, ..
            }) => {
                assert_eq!(src_port, 9000);
                assert_eq!(dst_port, 8080);
            }
            other => panic!("Expected Redirect variant, got {:?}", other),
        }
    }

    #[test]
    fn test_backward_compatibility_localhost() {
        let line = "SINGLE,2222,22,localhost";
        let result = parse_legacy_line(line);
        assert!(result.is_some());
        match result.unwrap() {
            RuntimeCell::Rule(NftCell::Single {
                sport,
                dport,
                domain,
                ..
            }) => {
                assert_eq!(sport, 2222);
                assert_eq!(dport, 22);
                assert_eq!(domain, "localhost");
            }
            other => panic!("Expected Single variant, got {:?}", other),
        }
    }
}
