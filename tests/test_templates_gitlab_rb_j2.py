# ruff: noqa: S101
# Testing library/framework: pytest with Jinja2 rendering (no new deps introduced).
# These tests focus on the gitlab.rb.j2 template logic from the PR diff.

import json
import pytest
import yaml
from jinja2 import Environment, BaseLoader, StrictUndefined
from pathlib import Path
from jinja2.runtime import Undefined
import re

# Resolve the path to the template relative to the repo root
TEMPLATE_PATH = Path(__file__).parent.parent / "templates" / "gitlab.rb.j2"
# Ensure the template file exists so tests fail with a clear error if the path changes
assert TEMPLATE_PATH.exists(), f"Template not found at {TEMPLATE_PATH}. Check repository layout or adjust TEMPLATE_PATH."

DEFAULTS_PATH = Path(__file__).parent.parent / "defaults" / "main.yml"

def _load_defaults():
    if not DEFAULTS_PATH.exists():
        return {}
    with open(DEFAULTS_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
        return data if data else {}

def _deep_merge(base: dict, override: dict) -> dict:
    result = base.copy()
    for k, v in override.items():
        if (
            k in result
            and isinstance(result[k], dict)
            and isinstance(v, dict)
        ):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result

# Read the actual template content
with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
    TEMPLATE_SRC = f.read()

def render(**ctx) -> str:
    env = Environment(
        loader=BaseLoader(),
        autoescape=False,
        undefined=StrictUndefined,
        trim_blocks=False,
        lstrip_blocks=False,
    )

    # Add filters used in the template
    def _to_json_safe(value):
        # Treat Jinja2 Undefined as JSON null to avoid TypeError during rendering
        if isinstance(value, Undefined):
            return "null"
        try:
            return json.dumps(value)
        except TypeError:
            # Fallback: stringify non-serializable objects
            return json.dumps(str(value))

    env.filters["to_json"] = _to_json_safe
    # Jinja2's regex_search is available via 'select' tests/filters in Ansible, but not vanilla Jinja2.
    # For this test, we provide a minimal implementation of regex_search as a filter.

    def regex_search(s: str, pattern: str):
        return re.search(pattern, s or "") is not None

    env.filters["regex_search"] = regex_search
    tmpl = env.from_string(TEMPLATE_SRC)
    defaults = _load_defaults()
    merged_ctx = _deep_merge(defaults, ctx)
    return tmpl.render(**merged_ctx)


def _base_ctx():
    return {
        "gitlab_external_url": "https://gitlab.example.com",
        "gitlab_version": "17.10.0",
    }


def test_external_url_and_basic_settings_present():
    out = render(**_base_ctx())
    assert 'external_url "https://gitlab.example.com"' in out

@pytest.mark.parametrize(
    "backup_defined",
    [
        (True),
        (False),
    ],
)
def test_backup(backup_defined):
    ctx = _base_ctx()
    if backup_defined:
      ctx["gitlab_backup_path"] = "/var/opt/gitlab/backups"
      ctx["gitlab_backup_keep_time"] = 604800

    out = render(**ctx)

    if backup_defined:
      assert "gitlab_rails['backup_path'] = '/var/opt/gitlab/backups'" in out
      assert "gitlab_rails['backup_keep_time'] = 604800" in out
    else:
      assert "gitlab_rails['backup_path'] = '/var/opt/gitlab/backups'" not in out
      assert "gitlab_rails['backup_keep_time'] = 604800" not in out

@pytest.mark.parametrize(
    "tz_defined",
    [
        (True),
        (False),
    ],
)
def test_time_zone_block_guards(tz_defined):
    ctx = _base_ctx()
    if tz_defined:
        ctx["gitlab_time_zone"] = "UTC"
    out = render(**ctx)
    if tz_defined:
        assert "gitlab_rails['time_zone'] = \"UTC\"" in out
    else:
        assert "gitlab_rails['time_zone']" not in out

@pytest.mark.parametrize(
    "theme_expected",
    [
        (True),
        (False),
    ],
)
def test_default_theme_block_guards(theme_expected):
    ctx = _base_ctx()
    if theme_expected:
        ctx["gitlab_default_theme"] = 2
    out = render(**ctx)
    if theme_expected:
        assert "gitlab_rails['gitlab_default_theme'] = \'2\'" in out
    else:
        assert "gitlab_rails['gitlab_default_theme']" not in out

@pytest.mark.parametrize(
    "redirect",
    [
        (True),
        (False),
    ],
)
def test_ssl_redirect(redirect):
    ctx = _base_ctx()

    if redirect:
      ctx["gitlab_redirect_http_to_https"] = True
        
    out = render(**ctx)
    if redirect:
      assert "nginx['redirect_http_to_https'] = true" in out
    else:
      assert "nginx['redirect_http_to_https']" not in out

@pytest.mark.parametrize(
    "certificate",
    [
        (True),
        (False),
    ],
)
def test_ssl_cert_blocks(certificate):
    ctx = _base_ctx()
    if certificate:
        ctx.update(
            {
                "gitlab_ssl_certificate": "/etc/gitlab/ssl/fullchain.pem",
                "gitlab_ssl_certificate_key": "/etc/gitlab/ssl/privkey.pem",
            }
        )
    out = render(**ctx)
    if certificate:
      assert "nginx['ssl_certificate'] = \"/etc/gitlab/ssl/fullchain.pem\"" in out
      assert "nginx['ssl_certificate_key'] = \"/etc/gitlab/ssl/privkey.pem\"" in out
    else:
      assert "nginx['ssl_certificate']" not in out
      assert "nginx['ssl_certificate_key']" not in out


def test_letsencrypt_block_with_list_and_booleans_and_strings():
    ctx = _base_ctx()
    ctx.update(
        {
            "gitlab_letsencrypt_enable": True,
            "gitlab_letsencrypt_contact_emails": ["a@example.com", "b@example.com"],
            "gitlab_letsencrypt_auto_renew_hour": "0",
            "gitlab_letsencrypt_auto_renew_minute": "30",
            "gitlab_letsencrypt_auto_renew_day_of_month": "1",
            "gitlab_letsencrypt_auto_renew": True,
        }
    )
    out = render(**ctx)
    assert "letsencrypt['enable'] = true" in out
    assert 'letsencrypt[\'contact_emails\'] = ["a@example.com", "b@example.com"]' in out
    assert "letsencrypt['auto_renew_hour'] = \"0\"" in out
    assert "letsencrypt['auto_renew_minute'] = \"30\"" in out
    assert "letsencrypt['auto_renew_day_of_month'] = \"1\"" in out
    assert "letsencrypt['auto_renew'] = true" in out


@pytest.mark.parametrize(
    "version,expect_legacy",
    [
        ("9.5.0", True),
        ("14.10.5", True),
        ("16.11.0", True),
        ("17.3.2", True),  # 17.[0-9].* -> legacy
        ("17.10.0", False),
        ("18.0.0", False),
    ],
)
def test_git_data_dirs_vs_gitaly_configuration_switch(version, expect_legacy):
    ctx = _base_ctx()
    ctx["gitlab_version"] = version
    ctx["gitlab_git_data_dir"] = "/var/opt/gitlab/git-data"
    out = render(**ctx)
    if expect_legacy:
        assert (
            'git_data_dirs({"default" => {"path" => "/var/opt/gitlab/git-data"} })'
            in out
        )
        assert "gitaly['configuration']" not in out
    else:
        assert "gitaly['configuration'] = {" in out
        assert "name: 'default'," in out
        assert 'path: "/var/opt/gitlab/git-data/repositories"' in out
        assert "git_data_dirs(" not in out


def test_email_block_present_only_when_enabled_and_values_quoted():
    ctx = _base_ctx()
    ctx.update(
        {
            "gitlab_email_enabled": True,
            "gitlab_email_from": "gitlab@ex.com",
            "gitlab_email_display_name": "GL",
            "gitlab_email_reply_to": "noreply@ex.com",
        }
    )
    out = render(**ctx)
    assert "gitlab_rails['gitlab_email_enabled'] = true" in out
    assert "gitlab_rails['gitlab_email_from'] = 'gitlab@ex.com'" in out
    assert "gitlab_rails['gitlab_email_display_name'] = 'GL'" in out
    assert "gitlab_rails['gitlab_email_reply_to'] = 'noreply@ex.com'" in out


def test_nginx_listen_port_and_https_defined_guards():
    ctx = _base_ctx()
    ctx.update(
        {
            "gitlab_nginx_listen_port": "8080",
            "gitlab_nginx_listen_https": True,
        }
    )
    out = render(**ctx)
    assert "nginx['listen_port'] = \"8080\"" in out
    assert "nginx['listen_https'] = true" in out


def test_smtp_full_block_with_nested_optionals():
    ctx = _base_ctx()
    ctx.update(
        {
            "gitlab_email_enabled": True,
            "gitlab_email_from": "info@ex.com",
            "gitlab_smtp_enable": True,
            "gitlab_smtp_address": "smtp.ex.com",
            "gitlab_smtp_port": 587,
            "gitlab_smtp_user_name": "user",
            "gitlab_smtp_password": "pass",
            "gitlab_smtp_domain": "ex.com",
            "gitlab_smtp_authentication": "login",
            "gitlab_smtp_enable_starttls_auto": True,
            "gitlab_smtp_tls": False,
            "gitlab_smtp_openssl_verify_mode": "none",
            "gitlab_smtp_ca_path": "/etc/ssl/certs",
            "gitlab_smtp_ca_file": "/etc/ssl/cert.pem",
        }
    )
    out = render(**ctx)
    assert "gitlab_rails['smtp_enable'] = true" in out
    assert "gitlab_rails['gitlab_email_from'] = 'info@ex.com'" in out
    assert "gitlab_rails['smtp_address'] = 'smtp.ex.com'" in out
    assert "gitlab_rails['smtp_port'] = 587" in out
    assert "gitlab_rails['smtp_user_name'] = 'user'" in out
    assert "gitlab_rails['smtp_password'] = 'pass'" in out
    assert "gitlab_rails['smtp_domain'] = 'ex.com'" in out
    assert "gitlab_rails['smtp_authentication'] = 'login'" in out
    assert "gitlab_rails['smtp_enable_starttls_auto'] = true" in out
    assert "gitlab_rails['smtp_tls'] = false" in out
    assert "gitlab_rails['smtp_openssl_verify_mode'] = 'none'" in out
    assert "gitlab_rails['smtp_ca_path'] = '/etc/ssl/certs'" in out
    assert "gitlab_rails['smtp_ca_file'] = '/etc/ssl/cert.pem'" in out

@pytest.mark.parametrize(
    "ssl_verify_enabled",
    [
        (True),
        (False),
    ],
)
def test_two_way_ssl_client_auth_blocks(ssl_verify_enabled):
    ctx = _base_ctx()
    if ssl_verify_enabled:
        ctx.update(
            {
                "gitlab_nginx_ssl_verify_client": "on",
                "gitlab_nginx_ssl_client_certificate": "/etc/gitlab/ssl/client-ca.pem",
            }
        )
    out = render(**ctx)
    if ssl_verify_enabled:
        assert "nginx['ssl_verify_client'] = \"on\"" in out
        assert "nginx['ssl_client_certificate'] = \"/etc/gitlab/ssl/client-ca.pem\"" in out
    else:
        assert "nginx['ssl_verify_client']" not in out
        assert "nginx['ssl_client_certificate']" not in out

def test_registry_blocks_when_enabled():
    ctx = _base_ctx()
    ctx.update(
        {
            "gitlab_registry_enable": True,
            "gitlab_registry_external_url": "https://registry.ex.com",
            "gitlab_registry_nginx_ssl_certificate": "/etc/ssl/reg.crt",
            "gitlab_registry_nginx_ssl_certificate_key": "/etc/ssl/reg.key",
        }
    )
    out = render(**ctx)
    assert "registry['enable'] = true" in out
    assert 'registry_external_url "https://registry.ex.com"' in out
    assert "registry_nginx['ssl_certificate'] = \"/etc/ssl/reg.crt\"" in out
    assert "registry_nginx['ssl_certificate_key'] = \"/etc/ssl/reg.key\"" in out

@pytest.mark.parametrize(
    "pages_defined",
    [
        (True),
        (False),
    ],
)
def test_pages_blocks(pages_defined):
    ctx = _base_ctx()
    if pages_defined:
        ctx["gitlab_pages_external_url"] = "https://pages.ex.com"
    out = render(**ctx)
    if pages_defined:
        assert 'pages_external_url "https://pages.ex.com"' in out
    else:
        assert 'pages_external_url' not in out

def test_ldap_block_with_extra_settings_appended_and_true_literal():
    ctx = _base_ctx()
    ctx.update(
        {
            "gitlab_ldap_enabled": True,
            "gitlab_ldap_host": "ldap.ex.com",
            "gitlab_ldap_port": 389,
            "gitlab_ldap_uid": "uid",
            "gitlab_ldap_method": "plain",
            "gitlab_ldap_bind_dn": "cn=admin,dc=ex,dc=com",
            "gitlab_ldap_password": "secret",
            "gitlab_ldap_base": "dc=ex,dc=com",
            "gitlab_ldap_extra_settings": [
                {"key": "timeout", "value": "30"},
                {"key": "active_directory", "value": "true"},
            ],
        }
    )
    out = render(**ctx)
    assert "gitlab_rails['ldap_enabled'] = true" in out
    assert "'host' =>  'ldap.ex.com'," in out
    assert "'port' => 389" in out
    assert "'allow_username_or_email_login' => true" in out
    # Extra settings appear as kv pairs under the servers map
    assert "    'timeout' => '30'," in out
    assert "    'active_directory' => 'true'," in out


def test_extra_settings_plain_and_non_string_values_unquoted():
    ctx = _base_ctx()
    ctx.update(
        {
            "gitlab_extra_settings": [
                {
                    "gitlab_rails": [
                        {"key": "max_request_duration", "value": 60, "type": "plain"},
                        {
                            "key": "monitoring_whitelist",
                            "value": ["10.0.0.1", "10.0.0.2"],
                        },
                        {"key": "some_flag", "value": True, "type": "plain"},
                    ]
                },
                {
                    "nginx": [
                        {
                            "key": "client_max_body_size",
                            "value": "100m",
                            "type": "plain",
                        },
                    ]
                },
            ]
        }
    )
    out = render(**ctx)
    # numeric plain (unquoted)
    assert "gitlab_rails['max_request_duration'] = 60" in out
    # list becomes unquoted JSON-like representation when not string
    assert (
        "gitlab_rails['monitoring_whitelist'] = ['10.0.0.1', '10.0.0.2']" in out
        or 'gitlab_rails[\'monitoring_whitelist\'] = ["10.0.0.1", "10.0.0.2"]' in out
    )
    # boolean plain
    assert (
        "gitlab_rails['some_flag'] = True" in out
        or "gitlab_rails['some_flag'] = true" in out
    )
    # nginx plain string (explicitly plain → unquoted)
    assert "nginx['client_max_body_size'] = 100m" in out
