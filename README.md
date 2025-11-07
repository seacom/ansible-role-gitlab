# Ansible Role: GitLab

This Ansible role installs and upgrades GitLab on RedHat/CentOS and Debian/Ubuntu systems.

It is a maintained fork of the original (now unmaintained) [Geerlingguy GitLab role](https://github.com/geerlingguy/ansible-role-gitlab). Compared to the original version, this fork adds full support for GitLab upgrades and reduces the number of default variables enforced by the role.

## Requirements

- Ansible >= 2.10  
- Supported operating systems: Debian/Ubuntu or RedHat/CentOS

## Installation

```bash
ansible-galaxy install -r requirements.yml
```

## Variables

### Basic Configuration

**`gitlab_domain`** (default: `gitlab`)  
Domain where the GitLab instance will be accessible.

**`gitlab_external_url`** (default: `https://{{ gitlab_domain }}/`)  
Full external GitLab URL. You may specify a custom port (e.g., `https://gitlab:8443/`).

**`gitlab_edition`** (default: `gitlab-ce`)  
GitLab edition to install:  
- `gitlab-ce` (Community Edition)  
- `gitlab-ee` (Enterprise Edition)

**`gitlab_version`** (default: `''`)  
Specific version to install (e.g., `11.4.0-ce.0` for Debian/Ubuntu or `11.4.0-ce.0` for RedHat/CentOS).  
If empty, the latest available GitLab version is installed.

**`gitlab_config_template`** (default: `gitlab.rb.j2`)  
Custom GitLab configuration template. To use a custom template:
- Create a `templates` directory next to your playbook  
- Add your template file (e.g., `templates/mygitlab.rb.j2`)  
- Set: `gitlab_config_template: mygitlab.rb.j2`

---

### Storage and Backup

**`gitlab_git_data_dir`** (default: `/var/opt/gitlab/git-data`)  
Directory containing all Git repositories.

**`gitlab_backup_path`** (default: `/var/opt/gitlab/backups`)  
Directory used for storing GitLab backups.

**`gitlab_backup_keep_time`** (default: `604800`)  
Backup retention time in seconds (default: 7 days).

---

### SSL Configuration

**`gitlab_redirect_http_to_https`** (default: `true`)  
Automatically redirect HTTP requests to HTTPS.

**`gitlab_ssl_certificate`** (default: `/etc/gitlab/ssl/{{ gitlab_domain }}.crt`)  
Path to the SSL certificate.

**`gitlab_ssl_certificate_key`** (default: `/etc/gitlab/ssl/{{ gitlab_domain }}.key`)  
Path to the SSL key.

**`gitlab_create_self_signed_cert`** (default: `false`)  
Create a self-signed certificate automatically.

**`gitlab_self_signed_cert_subj`** (default: `/C=US/ST=Missouri/L=Saint Louis/O=IT/CN={{ gitlab_domain }}`)  
Subject used when generating the self-signed certificate.

---

### Let's Encrypt

**`gitlab_letsencrypt_enable`** (default: `false`)  
Enable Let's Encrypt certificate provisioning.

**`gitlab_letsencrypt_contact_emails`** (default: `["gitlab@example.com"]`)  
Contact email addresses for Let's Encrypt notifications.

**`gitlab_letsencrypt_auto_renew`** (default: `true`)  
Enable automatic certificate renewal.

Scheduling settings:
- **`gitlab_letsencrypt_auto_renew_hour`** (default: `1`)
- **`gitlab_letsencrypt_auto_renew_minute`** (default: `30`)
- **`gitlab_letsencrypt_auto_renew_day_of_month`** (default: `*/7`)

---

### LDAP Authentication

**`gitlab_ldap_enabled`** (default: `false`)  
Enable LDAP authentication.

Common parameters:
- **`gitlab_ldap_host`** (default: `example.com`)
- **`gitlab_ldap_port`** (default: `389`)
- **`gitlab_ldap_uid`** (default: `sAMAccountName`)
- **`gitlab_ldap_method`** (default: `plain`)
- **`gitlab_ldap_bind_dn`** (default: `CN=Username,CN=Users,DC=example,DC=com`)
- **`gitlab_ldap_password`** (default: `password`)
- **`gitlab_ldap_base`** (default: `DC=example,DC=com`)

For multi-server setups, use the `gitlab_extra_settings` array.

---

### Email Configuration

**`gitlab_email_enabled`** (default: `false`)  
Enable GitLab outbound email.

**`gitlab_email_from`** (default: `gitlab@example.com`)  
**`gitlab_email_display_name`** (default: `GitLab`)  
**`gitlab_email_reply_to`** (default: `gitlab@example.com`)  

---

### SMTP Configuration

**`gitlab_smtp_enable`** (default: `false`)  
Enable SMTP for email delivery.

SMTP parameters:
- **`gitlab_smtp_address`** (default: `smtp.server`)
- **`gitlab_smtp_port`** (default: `465`)
- **`gitlab_smtp_user_name`** (default: `smtp user`)
- **`gitlab_smtp_password`** (default: `smtp password`)
- **`gitlab_smtp_domain`** (default: `example.com`)
- **`gitlab_smtp_authentication`** (default: `login`)
- **`gitlab_smtp_enable_starttls_auto`** (default: `true`)
- **`gitlab_smtp_tls`** (default: `false`)
- **`gitlab_smtp_openssl_verify_mode`** (default: `none`)
- **`gitlab_smtp_ca_path`** (default: `/etc/ssl/certs`)
- **`gitlab_smtp_ca_file`** (default: `/etc/ssl/certs/ca-certificates.crt`)

---

### NGINX Configuration

**`gitlab_nginx_listen_port`** (default: `8080`)  
NGINX listening port (useful when putting GitLab behind a reverse proxy).

**`gitlab_nginx_listen_https`** (default: `false`)  
Disable HTTPS on NGINX when SSL termination happens upstream.

**`gitlab_nginx_ssl_verify_client`** (default: `""`)  
**`gitlab_nginx_ssl_client_certificate`** (default: `""`)  
Enable mutual TLS authentication if required.

---

### Other Settings

**`gitlab_time_zone`** (default: `UTC`)  
GitLab timezone.

**`gitlab_default_theme`** (default: `2`)  
Default UI theme for all users.

**`gitlab_dependencies`**  
System packages required by GitLab:

```yaml
- openssh-server
- postfix
- curl
- openssl
- tzdata
```

**`gitlab_download_validate_certs`** (default: `true`)  
Validate certificates when downloading the GitLab installation script.

**`gitlab_extra_settings`**  
Extend GitLab configuration with additional custom values:

```yaml
gitlab_extra_settings:
  - gitlab_rails:
      - key: "trusted_proxies"
        value: "['foo', 'bar']"
      - key: "env"
        type: "plain"
        value: |
          {
            "http_proxy"  => "https://my_http_proxy.company.com:3128",
            "https_proxy" => "https://my_http_proxy.company.com:3128",
            "no_proxy"    => "localhost, 127.0.0.1, company.com"
          }
  - unicorn:
      - key: "worker_processes"
        value: 5
```

---

## Usage Example

```yaml
- hosts: gitlab_servers
  become: yes
  vars:
    gitlab_domain: gitlab.example.com
    gitlab_external_url: "https://gitlab.example.com/"
    gitlab_edition: gitlab-ce
    gitlab_letsencrypt_enable: true
    gitlab_letsencrypt_contact_emails:
      - admin@example.com
  roles:
    - ansible-role-gitlab
```

### LDAP Example

```yaml
- hosts: gitlab_servers
  become: yes
  vars:
    gitlab_external_url: "https://gitlab.company.com/"
    gitlab_ldap_enabled: true
    gitlab_ldap_host: "ldap.company.com"
    gitlab_ldap_port: "389"
    gitlab_ldap_uid: "sAMAccountName"
    gitlab_ldap_bind_dn: "CN=GitLab,CN=Users,DC=company,DC=com"
    gitlab_ldap_password: "secure_password"
    gitlab_ldap_base: "DC=company,DC=com"
  roles:
    - ansible-role-gitlab
```

---

## Upgrade Notes

### v18.0.0

**Migration from `git_data_dirs`:**  
This role automatically handles the required migration by adding the `/repository` suffix.  
No variable changes are required.  
See the [GitLab documentation](https://docs.gitlab.com/omnibus/settings/configuration/#migrating-from-git_data_dirs).

---

## Default Credentials

Default administrator credentials:

```
Username: root
Password: 5iveL!fe
```

⚠️ **Important:** Log in immediately after installation and change these credentials.

---

## License

MIT / BSD

## Author Information

This fork is maintained by [Seacom srl — Società Benefit](https://seacom.it).  
The original role was authored in 2014 by [Jeff Geerling](http://jeffgeerling.com/), author of *Ansible for DevOps*.
