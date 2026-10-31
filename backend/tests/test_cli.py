from attackgraph.__main__ import main


def test_analyze_and_path_commands(capsys):
    assert main(["analyze"]) == 0
    out = capsys.readouterr().out
    assert "incidents=4" in out and "INC-0002 Critical" in out
    assert main(["path", "user:sameer", "database:FINANCE-DB", "--hops", "5"]) == 0
    out = capsys.readouterr().out
    assert "user:sameer -> host:WS-014" in out and "rejected (temporally impossible)" in out


def test_env_file_loader(tmp_path, monkeypatch):
    from attackgraph.config import load_env_file
    f = tmp_path / ".env"
    f.write_text("# comment\nAGL_TEST_A=1\nAGL_TEST_B='two'\nAGL_TEST_EXISTING=new\nBROKEN LINE\n")
    monkeypatch.setenv("AGL_TEST_EXISTING", "old")
    monkeypatch.delenv("AGL_TEST_A", raising=False)
    monkeypatch.delenv("AGL_TEST_B", raising=False)
    assert load_env_file(f) == 2
    import os
    assert os.environ["AGL_TEST_A"] == "1" and os.environ["AGL_TEST_B"] == "two" and os.environ["AGL_TEST_EXISTING"] == "old"
    monkeypatch.delenv("AGL_TEST_A")
    monkeypatch.delenv("AGL_TEST_B")
