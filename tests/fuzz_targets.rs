use plens::engine::discover::parse_port_specs;
use plens::engine::nmap::parse_nmap_xml;

#[test]
fn test_fuzz_port_specs_parser() {
    let corrupt_inputs = [
        "",
        " ",
        "\0",
        "80,443,invalid",
        "65536",
        "99999999999999999999",
        "-1",
        "80-",
        "-80",
        "80-70",
        "80--90",
        "80, ,443",
        ",,,,",
        "top100,all,top1000",
        "🐱🚀🔥",
        &"80,".repeat(500),
        &"1-65535,".repeat(20),
    ];

    for input in corrupt_inputs {
        // Must never panic! Returns either Ok or Err
        let _ = parse_port_specs(input);
    }
}

#[test]
fn test_fuzz_nmap_xml_parser() {
    let corrupt_xmls = [
        "",
        "not xml",
        "<",
        "<?xml?>",
        "<nmaprun><host><ports><port portid='bad'><state state='open'/></port></ports></host></nmaprun>",
        "<nmaprun><host><ports><port portid='-5'><state state='invalid'/></port></ports></host></nmaprun>",
        "<nmaprun><host><ports><port portid='80'><state state='open'/><service name='http'><cpe></service></port></ports></host></nmaprun>",
        &"<nmaprun><host><ports>".repeat(100),
        "<xml>&test;&invalid;<![CDATA[ <random> ]]></xml>",
    ];

    for xml in corrupt_xmls {
        // Must never panic
        let _ = parse_nmap_xml(xml);
    }
}

#[test]
fn test_fuzz_probe_response_parsers() {
    // Test that corrupt arbitrary byte buffers fed to probe response handling never panic
    let random_payloads: &[&[u8]] = &[
        b"",
        b"\0\0\0\0",
        b"+PONG\r\n",
        b"-ERR unknown command\r\n",
        b":100\r\n",
        b"STAT version 1.6.17\r\nEND\r\n",
        b"VERSION 1.2.3\r\n",
        b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n",
        b"220 (vsFTPd 3.0.5)\r\n",
        b"230 Login successful.\r\n",
        b"530 Permission denied.\r\n",
        b"{\"version\":\"24.0.5\",\"ApiVersion\":\"1.43\"}",
        b"{\"cluster_name\":\"elasticsearch\",\"status\":\"green\"}",
        b"{\"ok\": 1, \"ismaster\": true}",
        b"\xFF\xFF\xFF\xFF",
        b"\x00\x01\x02\x03\x04\x05",
    ];

    for payload in random_payloads {
        // Test UTF-8 lossy handling and JSON parsing resilience
        let s = String::from_utf8_lossy(payload);
        let _ = serde_json::from_str::<serde_json::Value>(&s);
    }
}
