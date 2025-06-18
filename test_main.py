import os
import shutil
import tempfile
import pytest
from unittest import mock
import main

@pytest.fixture(autouse=True)
def temp_cwd(monkeypatch):
    # Use a temporary directory as the working directory for isolation
    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.chdir(tmpdir)
        yield

@pytest.fixture
def mock_global_config():
    return {
        "server": {
            "ssl_certfile": "cert.pem",
            "ssl_keyfile": "key.pem",
            "host": "localhost",
            "port": 8765,
        }
    }

def test_server_init_creates_files_and_admin(monkeypatch, mock_global_config):
    # Mock global_config
    monkeypatch.setattr(main, "global_config", mock_global_config)
    # Mock SQLAlchemy Base and Session
    mock_base = mock.Mock()
    mock_engine = mock.Mock()
    monkeypatch.setattr(main, "Base", mock_base)
    monkeypatch.setattr(main, "engine", mock_engine)
    mock_session_ctx = mock.MagicMock()
    monkeypatch.setattr(main, "Session", mock.Mock(return_value=mock_session_ctx))
    # Mock UserGroup
    mock_usergroup = mock.Mock()
    monkeypatch.setattr(main, "UserGroup", mock.Mock(return_value=mock_usergroup))
    # Mock create_user
    create_user_mock = mock.Mock()
    monkeypatch.setattr(main, "create_user", create_user_mock)
    # Patch cryptography modules
    monkeypatch.setattr(main, "x509", mock.Mock())
    monkeypatch.setattr(main, "NameOID", mock.Mock())
    monkeypatch.setattr(main, "hashes", mock.Mock())
    monkeypatch.setattr(main, "serialization", mock.Mock())
    monkeypatch.setattr(main, "rsa", mock.Mock())
    monkeypatch.setattr(main, "datetime", mock.Mock())

    main.server_init()

    # Check that admin_password.txt is created
    assert os.path.exists("admin_password.txt")
    # Check that ./content directory is created
    assert os.path.isdir("content")
    # Check that ./init file is created
    assert os.path.exists("init")
    # Check that create_user was called with admin
    create_user_mock.assert_called()
    args, kwargs = create_user_mock.call_args
    assert kwargs["username"] == "admin"
    # Check that cert and key files are created (even if empty)
    assert os.path.exists(mock_global_config["server"]["ssl_certfile"])
    assert os.path.exists(mock_global_config["server"]["ssl_keyfile"])

def test_main_calls_server_init_when_no_init(monkeypatch, mock_global_config):
    # Remove ./init if exists
    if os.path.exists("./init"):
        os.remove("./init")
    # Mock logger
    logger_mock = mock.Mock()
    monkeypatch.setattr(main, "getCustomLogger", mock.Mock(return_value=logger_mock))
    # Mock global_config
    monkeypatch.setattr(main, "global_config", mock_global_config)
    # Mock server_init
    server_init_mock = mock.Mock()
    monkeypatch.setattr(main, "server_init", server_init_mock)
    # Mock ssl context and serve
    ssl_ctx_mock = mock.Mock()
    monkeypatch.setattr(main.ssl, "SSLContext", mock.Mock(return_value=ssl_ctx_mock))
    serve_ctx = mock.MagicMock()
    serve_ctx.__enter__.return_value = serve_ctx
    serve_ctx.__exit__.return_value = None
    serve_ctx.serve_forever = mock.Mock()
    monkeypatch.setattr(main, "serve", mock.Mock(return_value=serve_ctx))
    # Mock handle_connection
    monkeypatch.setattr(main, "handle_connection", mock.Mock())

    main.main()

    server_init_mock.assert_called_once()
    logger_mock.info.assert_any_call("Database not initialized, initializing now...")
    serve_ctx.serve_forever.assert_called_once()

def test_main_does_not_call_server_init_when_init_exists(monkeypatch, mock_global_config):
    # Create ./init file
    with open("./init", "w") as f:
        f.write("init")
    # Mock logger
    logger_mock = mock.Mock()
    monkeypatch.setattr(main, "getCustomLogger", mock.Mock(return_value=logger_mock))
    # Mock global_config
    monkeypatch.setattr(main, "global_config", mock_global_config)
    # Mock server_init
    server_init_mock = mock.Mock()
    monkeypatch.setattr(main, "server_init", server_init_mock)
    # Mock ssl context and serve
    ssl_ctx_mock = mock.Mock()
    monkeypatch.setattr(main.ssl, "SSLContext", mock.Mock(return_value=ssl_ctx_mock))
    serve_ctx = mock.MagicMock()
    serve_ctx.__enter__.return_value = serve_ctx
    serve_ctx.__exit__.return_value = None
    serve_ctx.serve_forever = mock.Mock()
    monkeypatch.setattr(main, "serve", mock.Mock(return_value=serve_ctx))
    # Mock handle_connection
    monkeypatch.setattr(main, "handle_connection", mock.Mock())

    main.main()

    server_init_mock.assert_not_called()
    serve_ctx.serve_forever.assert_called_once()