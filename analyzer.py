import os
import json
import time
import re
import hashlib
import requests
from datetime import datetime, timedelta, timezone
from functools import lru_cache

RESULTS_DIR = 'analysis_results'


@lru_cache(maxsize=1024)
def fetch_hibp_range(prefix):
    try:
        url = f'https://api.pwnedpasswords.com/range/{prefix}'
        headers = {'User-Agent': 'VaultAnalyzer-Python/1.1'}  # Updated Agent
        # Consider adding an API key if HIBP requires it for higher volume
        # headers['hibp-api-key'] = 'YOUR_HIBP_API_KEY'
        response = requests.get(url, headers=headers, timeout=10)  # Increased timeout # noqa E501
        response.raise_for_status()  # Raise HTTPError for bad responses (4XX, 5XX) # noqa E501
        # Split efficiently
        return dict(line.split(':') for line in response.text.splitlines())
    except requests.exceptions.RequestException as e:
        print(f"HIBP Check network error for prefix {prefix}: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error during HIBP fetch for {prefix}: {e}")
        return None


def check_pwned_password(password, cache=None):
    if not password:
        return False, 0
    count = 0
    try:
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        hashes_dict = fetch_hibp_range(prefix)
        if hashes_dict is not None and suffix in hashes_dict:
            try:
                count = int(hashes_dict[suffix])
                return True, count
            except ValueError:  # Handle case where count isn't an int
                print(f"Warning: Invalid count from HIBP for {prefix}{suffix}")
                return True, 1  # Assume pwned if present but count invalid
    except Exception as e:
        print(f"Error during HIBP check logic: {e}")
    return False, 0


def analyze_password_strength(password):
    if not password:
        return 'No Password'
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    score = 0
    if length >= 16:
        score += 3
    elif length >= 12:
        score += 2
    elif length >= 8:
        score += 1
    if has_upper:
        score += 1
    if has_lower:
        score += 1
    if has_digit:
        score += 1
    if has_special:
        score += 1
    if score <= 2:
        return 'Very Weak'
    elif score <= 3:
        return 'Weak'
    elif score <= 4:
        return 'Fair'
    elif score <= 5:
        return 'Good'
    else:
        return 'Strong'


def detect_password_issues(password, username='', item_name='',
                           common_pass_list=None):
    issues = []
    if not password:
        return ['No password provided']
    if len(password) < 8:
        issues.append('Too short (< 8 characters)')
    if len(password) > 64:
        issues.append('Excessively long (> 64 characters)')  # Added check # noqa E501
    if password.isdigit():
        issues.append('Numbers only')
    if password.isalpha():
        issues.append('Letters only')
    if password.islower():
        issues.append('Lowercase only')
    if password.isupper():
        issues.append('Uppercase only')
    if not any(c.isdigit() for c in password):
        issues.append('No numbers')
    if not any(not c.isalnum() for c in password):
        issues.append('No special characters')  # noqa E501

    default_common = {'password', '123456', 'qwerty', 'admin', 'welcome',
                      'senha', '123456789', '12345678', 'abc123', '111111',
                      'p@ssword'}
    common_passwords = default_common.union(common_pass_list or set())
    if password.lower() in common_passwords:
        issues.append('Common password')

    keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', '123456', 'qazwsx',
                         '1qaz', '`123']
    pw_lower = password.lower()
    for pattern in keyboard_patterns:
        if pattern in pw_lower or pattern[::-1] in pw_lower:
            issues.append('Keyboard pattern detected')
            break

    for i in range(len(password) - 2):
        slice_ord = [ord(c) for c in password[i:i+3] if c.isascii()]  # Check sequence only for ascii # noqa E501
        if len(slice_ord) == 3:
            if ((slice_ord[1] == slice_ord[0] + 1 and
                 slice_ord[2] == slice_ord[1] + 1) or
                (slice_ord[1] == slice_ord[0] - 1 and
                 slice_ord[2] == slice_ord[1] - 1)):
                issues.append('Sequence detected')
                break

    if re.search(r'(.)\1{2,}', password):
        issues.append('Repeated characters')

    if username and len(username) >= 3 and username.lower() in pw_lower:
        issues.append('Contains username part')
    if item_name:
        name_parts = re.findall(r'\w+', item_name.lower())
        for part in name_parts:
            if len(part) >= 3 and part in pw_lower:
                issues.append('Contains item name part')
                break

    return issues


POTENTIAL_SECRET_PATTERNS = {
    'Potential AWS Key ID': re.compile(r'(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'),  # noqa E501
    'Potential AWS Secret Key': re.compile(r'(?i)(aws|amazon)?.{0,20}(secret|access|key).{0,20}(\s*[:=]\s*)?([\'"]?[a-zA-Z0-9/+]{40}[\'"]?)'),  # noqa E501
    'Potential Azure Client Secret': re.compile(r'[a-zA-Z0-9_\-\.]{30,}~[a-zA-Z0-9_\-\.]{8,}'),  # noqa E501
    'Potential Google API Key': re.compile(r'AIza[0-9A-Za-z\\-_]{35}'),
    'Potential Private Key': re.compile(r'-----BEGIN (RSA|EC|PGP|DSA|OPENSSH) PRIVATE KEY-----'),  # noqa E501
    'Generic High Entropy Secret': re.compile(r'(?i)(key|secret|token|password|passwd|pwd)\s*[:=]\s*([\'"]?[a-zA-Z0-9/+=\-_]{20,}[\'"]?)')  # noqa E501
}


def scan_text_for_secrets(text):
    findings = []
    if not text or not isinstance(text, str):
        return findings
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if len(line) > 2048:
            continue
        for name, pattern in POTENTIAL_SECRET_PATTERNS.items():
            match = pattern.search(line)
            if match:
                # Attempt to exclude clearly commented out lines
                trimmed_line = line.lstrip()
                if not trimmed_line.startswith(
                    ('#', '//', '/*', '--', '<!--')
                ):
                    context = line[:100] + ('...' if len(line) > 100 else '')
                    findings.append({'line_num': i + 1, 'finding': name,
                                     'context': context})
                    break
    return findings


def analyze_bitwarden_items(items, settings, cache):
    results = {
        'password_analysis': [], 'reused_passwords': {}, 'weak_passwords': [],
        'insecure_uris': [], 'old_passwords': [], 'pwned_passwords': [],
        'secrets_in_notes': [], 'secrets_in_fields': [],
        'problems_by_category': {}, 'total_items_by_type': {}
    }
    password_map = {}
    pw_age_years = settings.get('password_age_years', 1)
    password_age_threshold = (
        datetime.now(timezone.utc) - timedelta(days=int(pw_age_years * 365.25))
        if pw_age_years > 0 else None
    )
    check_hibp_setting = settings.get('check_hibp', True)
    analyze_notes_fields_setting = settings.get('analyze_notes_fields', True)

    common_pass_list = set()
    common_pass_file = settings.get('common_passwords_file')
    if common_pass_file and os.path.isfile(common_pass_file):  # Check isfile # noqa E501
        try:
            with open(common_pass_file, 'r', encoding='utf-8', errors='ignore') as f:  # noqa E501
                common_pass_list = {
                    line.strip().lower() for line in f if line.strip()
                }
        except Exception as e:
            print(f"Warning: Could not load common passwords file: {e}")

    for item in items:
        item_id = item.get('id', '')
        item_name = item.get('name', 'Unknown')
        item_type = item.get('type', 0)
        type_name = {1: 'Login', 2: 'SecureNote', 3: 'Card', 4: 'Identity'}\
            .get(item_type, 'Unknown')
        results['total_items_by_type'][type_name] = \
            results['total_items_by_type'].get(type_name, 0) + 1

        if item_type == 1:
            login_data = item.get('login', {})
            password = login_data.get('password', '')
            username = login_data.get('username', '')
            uris = login_data.get('uris', []) or []

            for uri_entry in uris:
                uri = uri_entry.get('uri', '')
                if uri and uri.startswith('http://'):
                    results['insecure_uris'].append({
                        'id': item_id, 'name': item_name, 'uri': uri
                    })
                    break

            revision_date_str = item.get('revisionDate', '')
            if revision_date_str and password_age_threshold:
                try:
                    revision_date = datetime.fromisoformat(
                        revision_date_str.replace('Z', '+00:00')
                    )
                    if revision_date < password_age_threshold:
                        results['old_passwords'].append({
                            'id': item_id,
                            'name': item_name,
                            'revisionDate': revision_date_str
                        })
                except ValueError:
                    pass

            strength = analyze_password_strength(password)
            issues = detect_password_issues(password, username, item_name,
                                            common_pass_list)
            is_pwned, pwn_count = (check_pwned_password(password, cache)
                                   if check_hibp_setting else (False, 0))

            if is_pwned:
                results['pwned_passwords'].append({
                    'id': item_id, 'name': item_name, 'username': username,
                    'count': pwn_count
                })
                issues.append(f'Password pwned ({pwn_count:,} times)')

            if password:
                if strength in ['Very Weak', 'Weak']:
                    results['weak_passwords'].append({
                        'id': item_id, 'name': item_name, 'username': username,
                        'strength': strength, 'issues': issues
                    })
                password_hash = hash(password)
                domains = [
                    u.get('uri', '').split('/')[2].lower().replace('www.', '')
                    if '://' in u.get('uri', '')
                    else u.get('uri', '').lower()
                    for u in uris if u.get('uri')
                ]
                entry_added = False
                for domain in domains:
                    if domain and not domain.isspace():
                        entry = {'id': item_id, 'name': item_name,
                                 'domain': domain, 'username': username}
                        if password_hash in password_map:
                            if not any(e['id'] == item_id for e in
                                       password_map[password_hash]):
                                password_map[password_hash].append(entry)
                                entry_added = True
                        else:
                            password_map[password_hash] = [entry]
                            entry_added = True
                if not entry_added and item_name:
                    entry = {'id': item_id, 'name': item_name,
                             'domain': 'No Domain', 'username': username}
                    if password_hash in password_map:
                        if not any(e['id'] == item_id for e in
                                   password_map[password_hash]):
                            password_map[password_hash].append(entry)
                    else:
                        password_map[password_hash] = [entry]

            item_analysis = {
                'id': item_id, 'name': item_name, 'username': username,
                'strength': strength, 'has_totp': bool(login_data.get('totp')),
                'is_pwned': is_pwned, 'issues': issues,
                'issue_count': len(issues), 'domains': uris
            }
            results['password_analysis'].append(item_analysis)

        if analyze_notes_fields_setting:
            if item_type == 2:
                note_text = item.get('notes')
                secret_findings = scan_text_for_secrets(note_text)
                if secret_findings:
                    results['secrets_in_notes'].append({
                        'id': item_id, 'name': item_name,
                        'findings': secret_findings
                    })

            fields = item.get('fields', [])
            if isinstance(fields, list):
                for field in fields:
                    if isinstance(field, dict):
                        field_value = field.get('value')
                        field_type = field.get('type', 0)  # 0:text, 1:hidden
                        if field_type in [0, 1] and isinstance(field_value, str):  # noqa E501
                            secret_findings = scan_text_for_secrets(field_value)  # noqa E501
                            if secret_findings:
                                results['secrets_in_fields'].append({
                                    'id': item_id, 'name': item_name,
                                    'field_name': field.get('name', 'Unnamed'),
                                    'findings': secret_findings
                                })

    reused_passwords_processed = {}
    for password_hash, sites in password_map.items():
        unique_items = {site['id']: site for site in sites}.values()
        if len(unique_items) > 1:
            reused_passwords_processed[password_hash] = list(unique_items)
    results['reused_passwords'] = reused_passwords_processed

    category_problems = {}
    for analysis in results['password_analysis']:
        if analysis['issues']:
            for issue in analysis['issues']:
                if issue.startswith('Password pwned'):
                    base_issue = 'Password pwned'
                    category_problems[base_issue] = \
                        category_problems.get(base_issue, 0) + 1
                else:
                    category_problems[issue] = \
                        category_problems.get(issue, 0) + 1
    if results['secrets_in_notes']:
        category_problems['Secrets in Notes'] = \
            len(results['secrets_in_notes'])
    if results['secrets_in_fields']:
        category_problems['Secrets in Custom Fields'] = \
            len(results['secrets_in_fields'])
    results['problems_by_category'] = category_problems

    return results


def calculate_bitwarden_summary(analysis_details, total_items, total_folders):
    password_analysis = analysis_details.get('password_analysis', [])
    reused_passwords = analysis_details.get('reused_passwords', {})
    pwned_passwords = analysis_details.get('pwned_passwords', [])
    insecure_uris = analysis_details.get('insecure_uris', [])
    old_passwords = analysis_details.get('old_passwords', [])
    secrets_in_notes = analysis_details.get('secrets_in_notes', [])
    secrets_in_fields = analysis_details.get('secrets_in_fields', [])

    strength_counts = {'Very Weak': 0, 'Weak': 0, 'Fair': 0, 'Good': 0,
                       'Strong': 0, 'No Password': 0}
    for item in password_analysis:
        strength_counts[item['strength']] = \
            strength_counts.get(item['strength'], 0) + 1

    security_score = 100.0  # Use float for calculation
    pwned_count = len(pwned_passwords)
    weak_count = strength_counts.get('Very Weak', 0) + \
        strength_counts.get('Weak', 0)
    reused_passwords_count = len(reused_passwords)
    secrets_count = len(secrets_in_notes) + len(secrets_in_fields)
    no_2fa_count = sum(1 for item in password_analysis
                       if not item.get('has_totp', False))
    insecure_uris_count = len(insecure_uris)
    old_passwords_count = len(old_passwords)

    security_score -= min(40.0, pwned_count * 10.0)
    security_score -= min(30.0, reused_passwords_count * 5.0)
    security_score -= min(25.0, secrets_count * 8.0)
    security_score -= min(25.0, weak_count * 5.0)
    security_score -= min(15.0, no_2fa_count * 1.0)
    security_score -= min(10.0, insecure_uris_count * 2.0)
    security_score -= min(5.0, old_passwords_count * 0.5)

    security_score = round(max(0.0, min(100.0, security_score)))

    critical_issues = (pwned_count + reused_passwords_count + weak_count +
                       secrets_count)
    warnings_count = no_2fa_count + insecure_uris_count + old_passwords_count

    risk_level = "Low"
    num_logins = len(password_analysis)
    if (security_score < 50 or pwned_count >= 1 or
            reused_passwords_count >= 5 or secrets_count >= 1):
        risk_level = "Critical"
    elif security_score < 75 or critical_issues >= 3:
        risk_level = "High"
    elif (security_score < 90 or
          (num_logins > 0 and warnings_count >= max(5, num_logins * 0.1))):
        risk_level = "Medium"

    return {
        'total_items': total_items, 'total_folders': total_folders,
        'total_logins': num_logins, 'security_score': security_score,
        'risk_level': risk_level, 'password_strength_counts': strength_counts,
        'reused_passwords_count': reused_passwords_count,
        'weak_passwords_count': weak_count,
        'pwned_passwords_count': pwned_count,
        'secrets_in_notes_count': len(secrets_in_notes),
        'secrets_in_fields_count': len(secrets_in_fields),
        'no_2fa_count': no_2fa_count,
        'insecure_uris_count': insecure_uris_count,
        'old_passwords_count': old_passwords_count,
        'critical_issues': critical_issues, 'warnings': warnings_count
    }


def generate_bitwarden_key_findings(analysis_details, limit=5):
    findings = []
    severity_map = {'Critical': 4, 'High': 3, 'Medium': 2, 'Warning': 1,
                    'Info': 0}

    pwned_passwords = analysis_details.get('pwned_passwords', [])
    if pwned_passwords:
        findings.append({
            'level': 'Critical', 'type': 'Pwned Passwords',
            'title': f'{len(pwned_passwords)} senha(s) encontrada(s) '
                     f'em vazamentos!',
            'description': f'Senhas para {len(pwned_passwords)} itens foram '
                           f'encontradas em vazamentos públicos (via HIBP). '
                           f'Altere-as IMEDIATAMENTE.',
            'recommendation': 'Altere imediatamente as senhas comprometidas '
                              'para senhas fortes e únicas. Ative 2FA.'
        })

    secrets_count = analysis_details.get('secrets_count', 0)
    if secrets_count > 0:
        findings.append({
            'level': 'Critical', 'type': 'Exposed Secrets',
            'title': f'Potenciais segredos ({secrets_count}) expostos em '
                     f'notas/campos!',
            'description': f'Encontrados {secrets_count} potenciais segredos '
                           f'(chaves, senhas) em texto claro em notas/campos.',
            'recommendation': 'Revise urgentemente. Mova segredos para campos '
                              'apropriados ou considere outra forma segura.'
        })

    reused_passwords = analysis_details.get('reused_passwords', {})
    if reused_passwords:
        if reused_passwords:
            most_reused_tuple = max(reused_passwords.items(),
                                    key=lambda item: len(item[1]),
                                    default=(None, []))
            most_reused_sites = most_reused_tuple[1]
            if most_reused_sites:
                reuse_count = len(most_reused_sites)
                example_sites_list = [
                    s['domain'] if s.get('domain') and
                    s['domain'] != 'No Domain' else s['name']
                    for s in most_reused_sites[:3]
                ]
                example_sites = ", ".join(filter(None, example_sites_list))
                findings.append({
                    'level': 'Critical', 'type': 'Password Reuse',
                    'title': f'Senha reutilizada em {reuse_count} locais',
                    'description': 'A mesma senha é usada em múltiplos locais,'
                                   ' incluindo: {}. Risco alto.'
                                   .format(example_sites),
                    'recommendation': 'Use senhas únicas e fortes para cada '
                                      'serviço. Use um gerador de senhas.'
                })

    weak_passwords_count = analysis_details.get('weak_passwords_count', 0)
    if weak_passwords_count > 0:
        findings.append({
            'level': 'High', 'type': 'Weak Passwords',
            'title': f'Encontradas {weak_passwords_count} senhas fracas',
            'description': 'Existem {weak_passwords_count} contas com senhas '
                           '"Very Weak" ou "Weak", fáceis de adivinhar.'
                           .format(weak_passwords_count=weak_passwords_count),
            'recommendation': 'Atualize para senhas fortes: longas (>12 '
                              'caracteres), complexas e não previsíveis.'
        })

    password_analysis = analysis_details.get('password_analysis', [])
    no_2fa_items = [item for item in password_analysis
                    if not item.get('has_totp', False)]
    if no_2fa_items:
        critical_domains_lower = {
            'google', 'gmail', 'microsoft', 'apple', 'amazon', 'facebook',
            'github', 'paypal', 'twitter', 'instagram', 'linkedin', 'dropbox',
            'slack'}
        critical_sites_without_2fa = []
        for item in no_2fa_items:
            uris_to_check = []
            raw_uris = item.get('domains', [])
            if isinstance(raw_uris, list):
                for u_entry in raw_uris:
                    uri = u_entry.get('uri', '') if isinstance(u_entry, dict)\
                        else u_entry
                    if isinstance(uri, str):
                        uris_to_check.append(uri)

            for uri in uris_to_check:
                if '://' in uri:
                    try:
                        domain_parts = uri.split('/')[2].lower().replace(
                            'www.', '').split('.')
                        primary_domain = domain_parts[-2] \
                            if len(domain_parts) >= 2 else domain_parts[0]
                        if primary_domain in critical_domains_lower:
                            critical_sites_without_2fa.append(item)
                            break
                    except IndexError:
                        pass

        if critical_sites_without_2fa:
            example_sites = ", ".join(sorted(list(set(
                item.get('name', 'Unknown') for item in
                critical_sites_without_2fa[:3]))))
            findings.append({
                'level': 'High', 'type': 'Missing 2FA',
                'title': f'Falta 2FA em {len(critical_sites_without_2fa)} '
                         f'site(s) crítico(s)',
                'description': f'Sites críticos sem 2FA, como: {example_sites}.',  # noqa E501
                'recommendation': 'Ative 2FA (app autenticador, se possível) '
                                  'para todos os serviços críticos urgente.'
            })
        elif len(no_2fa_items) > 5:
            findings.append({
                'level': 'Warning', 'type': 'Missing 2FA',
                'title': f'{len(no_2fa_items)} itens sem autenticação 2FA',
                'description': 'Um número considerável de logins não tem 2FA '
                               'configurado, aumentando o risco geral.',
                'recommendation': 'Ative 2FA para todos os serviços que '
                                  'suportam, priorizando os mais importantes.'
            })

    insecure_uris = analysis_details.get('insecure_uris', [])
    if insecure_uris:
        first_name = insecure_uris[0].get("name", "N/A")
        findings.append({
            'level': 'Warning', 'type': 'Insecure URIs',
            'title': f'{len(insecure_uris)} item(ns) usando HTTP',
            'description': f'Logins para sites como "{first_name}" usam URIs '
                           f'http://, enviando dados sem criptografia.',
            'recommendation': 'Verifique se suportam HTTPS (https://) e '
                              'atualize as URIs no Bitwarden.'
        })

    old_passwords = analysis_details.get('old_passwords', [])
    if old_passwords:
        findings.append({
            'level': 'Warning', 'type': 'Old Passwords',
            'title': f'{len(old_passwords)} senha(s) não alterada(s) há mais '
                     f'de um ano',
            'description': 'Senhas antigas (>1 ano) têm maior probabilidade '
                           'de estarem comprometidas.',
            'recommendation': 'Considere atualizar senhas antigas, '
                              'especialmente para serviços importantes.'
        })

    findings.sort(key=lambda x: severity_map.get(x.get('level', 'Info')),
                  reverse=True)

    if len(findings) < limit or not any(f['level'] == 'Critical' for f in findings):  # noqa E501
        total_logins = len(password_analysis)
        if total_logins > 0:
            score = analysis_details.get('security_score', 100)
            health_level = "good"
            level = 'Info'
            if score < 50:
                health_level = "critical"
                level = 'Warning'
            elif score < 75:
                health_level = "worrying"
                level = 'Info'
            elif score < 90:
                health_level = "fair"
                level = 'Info'

            pwned_c = analysis_details.get("pwned_passwords_count", 0)
            reused_c = analysis_details.get("reused_passwords_count", 0)
            weak_c = analysis_details.get("weak_passwords_count", 0)
            secrets_c = analysis_details.get("secrets_count", 0)

            findings.append({
                'level': level, 'type': 'Overall Health',
                'title': f'Saúde geral do cofre: {health_level}',
                'description': (
                    f'Score: {score}/100. Detalhes: {pwned_c} vazadas, '
                    f'{reused_c} reutilizadas, {weak_c} fracas, '
                    f'{secrets_c} segredos expostos.'
                ),
                'recommendation': 'Revise os achados críticos/altos. Mantenha '
                                  'boas práticas de senha.'
            })

    return findings[:limit]


def perform_analysis(bitwarden_data, scan_id, results_dir, settings, cache):
    start_time = time.time()
    if not isinstance(bitwarden_data, dict):
        raise ValueError("Invalid input: bitwarden_data must be a dictionary.")

    folders = bitwarden_data.get('folders', [])
    items = bitwarden_data.get('items', [])

    analysis_details = analyze_bitwarden_items(items, settings, cache)
    summary = calculate_bitwarden_summary(analysis_details, len(items),
                                          len(folders))

    analysis_details['security_score'] = summary.get('security_score')
    analysis_details['pwned_passwords_count'] = \
        summary.get('pwned_passwords_count')
    analysis_details['reused_passwords_count'] = \
        summary.get('reused_passwords_count')
    analysis_details['weak_passwords_count'] = \
        summary.get('weak_passwords_count')
    analysis_details['secrets_count'] = \
        summary.get('secrets_in_notes_count', 0) + \
        summary.get('secrets_in_fields_count', 0)

    key_findings = generate_bitwarden_key_findings(analysis_details)

    temp_keys = ['security_score', 'pwned_passwords_count',
                 'reused_passwords_count', 'weak_passwords_count',
                 'secrets_count']
    for key in temp_keys:
        if key in analysis_details:
            del analysis_details[key]

    strength_counts = summary.get('password_strength_counts', {})
    dist_series = [
        strength_counts.get('Very Weak', 0) + strength_counts.get('Weak', 0),
        strength_counts.get('Fair', 0), strength_counts.get('Good', 0),
        strength_counts.get('Strong', 0), strength_counts.get('No Password', 0)
    ]
    dist_labels = ['Weak/Very Weak', 'Fair', 'Good', 'Strong', 'No Password']
    filtered_series = [s for s, l in zip(dist_series, dist_labels) if s > 0]
    filtered_labels = [l for s, l in zip(dist_series, dist_labels) if s > 0]
    if not filtered_series:
        filtered_series, filtered_labels = (
            [1], ['No Data' if not items else 'Error/Unknown']
        )

    reused_passwords_list_output = []
    if analysis_details.get('reused_passwords'):
        reused_dict = analysis_details['reused_passwords']
        for password_hash, sites in reused_dict.items():
            formatted_items = []
            for site in sites:
                name = site.get('name', 'Unknown')
                domain = site.get('domain', 'Unknown')
                display_name = name if name != 'Unknown' else 'Item no name'
                display_domain = f" ({domain})" if domain != 'No Domain' and \
                    domain != 'Unknown' else " (No Domain)"
                formatted_items.append(f"{display_name}{display_domain}")
            reused_passwords_list_output.append({
                'count': len(sites),
                'items': formatted_items
            })
        analysis_details['reused_passwords'] = reused_passwords_list_output

    end_time = time.time()
    analysis_duration = round(end_time - start_time, 2)
    summary['analysis_duration_sec'] = analysis_duration

    all_results = {
        'scan_id': scan_id,
        'vault_path': f"Uploaded File ({summary.get('total_items', 0)} items)",
        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
        'summary': summary,
        'details': analysis_details,
        'findings': key_findings,
        'chart_data': {
             'score_trend': {'categories': [], 'series': []},
             'vulnerability_distribution': {'labels': filtered_labels,
                                            'series': filtered_series}
        }
    }

    if not os.path.exists(results_dir):
        os.makedirs(results_dir)
    filepath = os.path.join(results_dir, f"{scan_id}.json")
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(all_results, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"Error saving results file {filepath}: {e}")
        raise e

    print(f"Bitwarden analysis {scan_id} complete ({analysis_duration}s). "
          f"Results: {filepath}")
    return all_results
