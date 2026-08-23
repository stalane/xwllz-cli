from xwllz.config import ENV_KEYS, TOOLS, Config, load_config


def test_load_config_reads_env(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "abc123")
    cfg = load_config()
    assert cfg.has("shodan")
    assert cfg.keys["shodan"] == "abc123"
    assert not cfg.has("virustotal")


def test_load_config_detects_tools(monkeypatch):
    monkeypatch.setattr("xwllz.config.shutil.which", lambda name: f"/usr/bin/{name}")
    cfg = load_config()
    assert cfg.tool("nmap") == "/usr/bin/nmap"


def test_load_config_missing_tools(monkeypatch):
    monkeypatch.setattr("xwllz.config.shutil.which", lambda name: None)
    cfg = load_config()
    assert cfg.tool("nmap") is None


def test_env_key_map_has_expected_sources():
    assert "shodan" in ENV_KEYS
    assert "securitytrails" in ENV_KEYS
    assert "virustotal" in ENV_KEYS
    assert "nmap" in TOOLS
    assert "nuclei" in TOOLS


def test_config_defaults():
    cfg = Config()
    assert cfg.http_timeout == 8.0
    assert cfg.max_workers == 32