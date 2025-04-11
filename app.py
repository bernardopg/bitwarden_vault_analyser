import os
import json
import uuid
import csv
import io
from datetime import datetime
from flask import (Flask, render_template, request, redirect,
                   url_for, jsonify, flash, Response)
from flask_caching import Cache
from analyzer import perform_analysis as perform_bitwarden_analysis

RESULTS_DIR = 'analysis_results'
SETTINGS_FILE = 'settings.json'
DEFAULT_SETTINGS = {
  "password_age_years": 1,
  "check_hibp": True,
  "analyze_notes_fields": True,
  "common_passwords_file": None
}

if not os.path.exists(RESULTS_DIR):
    os.makedirs(RESULTS_DIR)

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(32))
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024  # 25MB upload limit

config = {
    "DEBUG": False,  # Set to False for production
    "CACHE_TYPE": "SimpleCache",
    "CACHE_DEFAULT_TIMEOUT": 300
}
app.config.from_mapping(config)
cache = Cache(app)


def load_settings():
    if not os.path.exists(SETTINGS_FILE):
        save_settings(DEFAULT_SETTINGS)
        return DEFAULT_SETTINGS
    try:
        with open(SETTINGS_FILE, 'r') as f:
            settings_data = json.load(f)
        current_settings = DEFAULT_SETTINGS.copy()
        current_settings.update(settings_data)
        return current_settings
    except (json.JSONDecodeError, IOError, TypeError) as e:
        app.logger.error(f"Error loading settings: {e}. Using defaults.")
        return DEFAULT_SETTINGS


def save_settings(settings_to_save):
    try:
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(settings_to_save, f, indent=4)
    except IOError as e:
        app.logger.error(f"Error saving settings: {e}")


STRENGTH_MAP = {
    'Very Weak': 0, 'Weak': 1, 'Fair': 2, 'Good': 3, 'Strong': 4,
    'No Password': -1
}


def sort_password_analysis(analysis_results):
    if (analysis_results and 'details' in analysis_results and
            'password_analysis' in analysis_results['details'] and
            isinstance(analysis_results['details']['password_analysis'],
                       list)):
        analysis_results['details']['password_analysis'] = sorted(
            analysis_results['details']['password_analysis'],
            key=lambda item: STRENGTH_MAP.get(item.get('strength',
                                                       'No Password'), -1)
        )
    return analysis_results


def format_reused_passwords(analysis_results):
    if not (analysis_results and 'details' in analysis_results and
            'reused_passwords' in analysis_results['details']):
        return analysis_results
    reused_passwords = analysis_results['details']['reused_passwords']
    if isinstance(reused_passwords, list):
        for reuse_info in reused_passwords:
            if not isinstance(reuse_info, dict):
                app.logger.warning(
                    f"Non-dict in reused_passwords: {reuse_info}"
                )
                continue
            if not isinstance(reuse_info.get('items'), list):
                app.logger.warning(
                    f"Non-list items in reuse_info: {reuse_info}"
                )
                reuse_info['items'] = []
        return analysis_results
    elif isinstance(reused_passwords, dict):
        reused_passwords_list = []
        for sites in reused_passwords.values():
            if not isinstance(sites, list):
                sites = []
            formatted_items = []
            for site in sites:
                if isinstance(site, dict):
                    name = site.get('name', 'Unknown')
                    domain = site.get('domain', 'Unknown')
                    display_name = (
                        name if name != 'Unknown' else 'Item no name'
                    )
                    display_domain = (f" ({domain})" if domain != 'No Domain'
                                      and domain != 'Unknown'
                                      else " (No Domain)")
                    formatted_items.append(f"{display_name}{display_domain}")
                else:
                    formatted_items.append("Invalid Site Entry")
            if len(sites) > 1:
                reused_passwords_list.append({
                    'count': len(sites),
                    'items': formatted_items
                })
        analysis_results['details']['reused_passwords'] = reused_passwords_list
    else:
        app.logger.warning(f"Unexpected type for reused_passwords: "
                           f"{type(reused_passwords)}. Resetting.")
        analysis_results['details']['reused_passwords'] = []
    return analysis_results


@app.route('/')
def index():
    last_scan_id = None
    analysis_results = None
    try:
        files = [os.path.join(RESULTS_DIR, f) for f in
                 os.listdir(RESULTS_DIR) if f.endswith('.json')]
        if files:
            latest_file = max(files, key=os.path.getmtime)
            last_scan_id = os.path.splitext(os.path.basename(latest_file))[0]
            with open(latest_file, 'r', encoding='utf-8') as f:
                analysis_results = json.load(f)
            analysis_results = format_reused_passwords(analysis_results)
            analysis_results = sort_password_analysis(analysis_results)
    except Exception as e:
        app.logger.error(f"Error loading latest analysis: {e}", exc_info=True)
        analysis_results = None
        last_scan_id = None
    return render_template('dashboard.html', scan_id=last_scan_id,
                           results=analysis_results)


@app.route('/analyze', methods=['POST'])
def analyze():
    if 'vault_file' not in request.files:
        flash('No file part in the request.', 'error')
        return redirect(url_for('index'))

    file = request.files['vault_file']
    if not file or file.filename == '':
        flash('No selected file.', 'error')
        return redirect(url_for('index'))

    if not file.filename.lower().endswith('.json'):
        flash('Invalid file type. Please upload a .json file.', 'error')
        return redirect(url_for('index'))

    try:
        file_content = file.read(app.config['MAX_CONTENT_LENGTH'] + 1)
        if len(file_content) > app.config['MAX_CONTENT_LENGTH']:
            flash(f"File exceeds maximum allowed size "
                  f"({app.config['MAX_CONTENT_LENGTH'] // 1024 // 1024}MB).",
                  'error')
            return redirect(url_for('index'))

        file_content_decoded = file_content.decode('utf-8')
        bitwarden_data = json.loads(file_content_decoded)

        if not isinstance(bitwarden_data, dict):
            raise ValueError("Uploaded file is not a JSON object.")
        if ('items' not in bitwarden_data or
                not isinstance(bitwarden_data['items'], list)):
            raise ValueError("JSON structure missing 'items' list.")

        scan_id = str(uuid.uuid4())
        settings = load_settings()

        perform_bitwarden_analysis(
            bitwarden_data=bitwarden_data,
            scan_id=scan_id,
            results_dir=RESULTS_DIR,
            settings=settings,
            cache=cache
        )

        flash(f'Analysis complete! Scan ID: {scan_id}', 'success')
        return redirect(url_for('view_report', scan_id=scan_id))

    except (UnicodeDecodeError, json.JSONDecodeError):
        flash('Invalid file content. Ensure it is a valid UTF-8 JSON file.',
              'error')
        return redirect(url_for('index'))
    except ValueError as ve:
        flash(f'Invalid JSON structure: {ve}', 'error')
        return redirect(url_for('index'))
    except Exception as e:
        app.logger.error(f"Analysis failed: {e}", exc_info=True)
        flash(f'An error occurred during analysis: {str(e)}', 'error')
        return redirect(url_for('index'))


@app.route('/report/<scan_id>')
def view_report(scan_id):
    # Basic validation of scan_id format
    try:
        uuid.UUID(scan_id, version=4)
    except ValueError:
        flash('Invalid Scan ID format.', 'error')
        return redirect(url_for('index'))

    filepath = os.path.join(RESULTS_DIR, f"{scan_id}.json")
    if not os.path.exists(filepath):
        # Prevent directory traversal attempt
        flash(f'Analysis report with ID {scan_id} not found.', 'error')
        return redirect(url_for('index'))

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            analysis_results = json.load(f)
        analysis_results = format_reused_passwords(analysis_results)
        analysis_results = sort_password_analysis(analysis_results)
        return render_template('dashboard.html', scan_id=scan_id,
                               results=analysis_results)
    except Exception as e:
        app.logger.error(f"Error loading report {scan_id}: {e}", exc_info=True)
        flash(f'Error loading report {scan_id}: {str(e)}', 'error')
        return redirect(url_for('index'))


@app.route('/history')
def history():
    scans = []
    try:
        files = [f for f in os.listdir(RESULTS_DIR) if f.endswith('.json')]
        for filename in files:
            scan_id = os.path.splitext(filename)[0]
            # Validate Scan ID format before proceeding
            try:
                uuid.UUID(scan_id, version=4)
            except ValueError:
                app.logger.warning(f"Skipping invalid filename/scan ID: {filename}") # noqa E501
                continue

            filepath = os.path.join(RESULTS_DIR, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                timestamp = data.get('timestamp', None)
                score = data.get('summary', {}).get('security_score', None)
                if not timestamp:
                    timestamp = datetime.fromtimestamp(
                        os.path.getmtime(filepath)
                    ).strftime("%Y-%m-%d %H:%M:%S")
                scans.append({'scan_id': scan_id, 'timestamp': timestamp,
                              'score': score})
            except Exception as e:
                app.logger.warning(f"Could not read data from {filename}: {e}")
                try:
                    mod_time = datetime.fromtimestamp(
                        os.path.getmtime(filepath)
                    ).strftime("%Y-%m-%d %H:%M:%S")
                    scans.append({'scan_id': scan_id, 'timestamp': mod_time,
                                  'score': None})
                except Exception:
                    scans.append({'scan_id': scan_id,
                                  'timestamp': 'Error reading time',
                                  'score': None})
        scans.sort(key=lambda x: x['timestamp'], reverse=True)
    except Exception as e:
        app.logger.error(f"Error listing history: {e}", exc_info=True)
        flash('Error loading analysis history.', 'error')
    return render_template('history.html', scans=scans)


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if request.method == 'POST':
        try:
            new_settings = {
                "password_age_years": int(request.form.get('password_age_years', 1)), # noqa E501
                "check_hibp": 'check_hibp' in request.form,
                "analyze_notes_fields": 'analyze_notes_fields' in request.form,
                "common_passwords_file": request.form.get('common_passwords_file') or None # noqa E501
            }
            if not (0 <= new_settings["password_age_years"] <= 10):
                raise ValueError("Pwd age must be between 0 and 10 years.")
            common_file = new_settings["common_passwords_file"]
            if common_file and not os.path.isfile(common_file): # Check if it's a file # noqa E501
                flash(f'Warning: Path "{common_file}" is not a valid file.',
                      'warning')
                # Reset if invalid
                new_settings["common_passwords_file"] = None

            save_settings(new_settings)
            flash('Settings updated successfully!', 'success')
        except ValueError as ve:
            flash(f'Invalid setting value: {ve}', 'error')
        except Exception as e:
            app.logger.error(f"Error saving settings: {e}", exc_info=True)
            flash('Failed to save settings.', 'error')
        return redirect(url_for('settings'))

    current_settings = load_settings()
    return render_template('settings.html', settings=current_settings)


@app.route('/report/<scan_id>/export/csv')
def export_csv(scan_id):
    try:
        uuid.UUID(scan_id, version=4)
    except ValueError:
        flash('Invalid Scan ID format.', 'error')
        return redirect(url_for('index'))

    filepath = os.path.join(RESULTS_DIR, f"{scan_id}.json")
    if not os.path.exists(filepath):
        flash(f'Analysis report with ID {scan_id} not found.', 'error')
        return redirect(url_for('index'))

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            results = json.load(f)

        si = io.StringIO()
        cw = csv.writer(si)

        cw.writerow(['Category', 'Metric', 'Value'])
        summary = results.get('summary', {})
        cw.writerow(['Summary', 'Scan ID', scan_id])
        cw.writerow(['Summary', 'Timestamp', results.get('timestamp', 'N/A')])
        for key, value in summary.items():
            if isinstance(value, dict):
                for sk, sv in value.items():
                    cw.writerow(['Summary', f"{key} - {sk}", sv])
            else:
                cw.writerow(['Summary', key.replace('_', ' ').title(), value])
        cw.writerow([])

        cw.writerow(['Level', 'Type', 'Title', 'Description',
                     'Recommendation'])
        findings = results.get('findings', [])
        for finding in findings:
            cw.writerow([
                finding.get('level'), finding.get('type'),
                finding.get('title'), finding.get('description'),
                finding.get('recommendation')
            ])
        cw.writerow([])

        cw.writerow(['Item Name', 'Username', 'Strength', 'Pwned', 'Issues'])
        password_analysis = results.get('details', {}).get('password_analysis', []) # noqa E501
        password_analysis_sorted = sorted(
            password_analysis,
            key=lambda item: STRENGTH_MAP.get(item.get('strength',
                                                       'No Password'), -1)
        )
        for item in password_analysis_sorted:
            cw.writerow([
                item.get('name'), item.get('username'), item.get('strength'),
                item.get('is_pwned'), "; ".join(item.get('issues', []))
            ])
        cw.writerow([])

        cw.writerow(['Reuse Group', 'Count', 'Items'])
        reused = results.get('details', {}).get('reused_passwords', [])
        for i, group in enumerate(reused):
            cw.writerow([f"Group {i+1}", group.get('count'),
                         ", ".join(group.get('items', []))])
        cw.writerow([])

        cw.writerow(['Item Name', 'Issue Type', 'Details'])
        items_no_totp = [item for item in password_analysis if not
                         item.get('has_totp', False)]
        for item in items_no_totp:
            cw.writerow([item.get('name'), 'No 2FA',
                         'Enable Two-Factor Authentication'])
        insecure_uris = results.get('details', {}).get('insecure_uris', [])
        for item in insecure_uris:
            cw.writerow([item.get('name'), 'Insecure URI (HTTP)', item.get('uri')]) # noqa E501
        old_passwords = results.get('details', {}).get('old_passwords', [])
        for item in old_passwords:
            rev_date = item.get('revisionDate', '').split('T')[0]
            cw.writerow([item.get('name'), 'Old Password (>1yr)',
                         f"Last Revised: {rev_date}"])

        secrets_notes = results.get('details', {}).get('secrets_in_notes', [])
        for item in secrets_notes:
            for finding in item.get('findings', []):
                cw.writerow([item.get('name'), 'Secret in Note',
                             f"L{finding.get('line_num')}: {finding.get('finding')}"]) # noqa E501
        secrets_fields = results.get('details', {}).get('secrets_in_fields', []) # noqa E501
        for item in secrets_fields:
            for finding in item.get('findings', []):
                cw.writerow([item.get('name'), 'Secret in Field',
                             f"{item.get('field_name')} L{finding.get('line_num')}: {finding.get('finding')}"]) # noqa E501

        output = si.getvalue()
        return Response(
            output,
            mimetype="text/csv",
            headers={"Content-disposition":
                     f"attachment; filename=vault_analysis_{scan_id}.csv"}
        )

    except Exception as e:
        app.logger.error(f"Error exporting CSV for {scan_id}: {e}",
                         exc_info=True)
        flash(f'Error exporting report {scan_id}: {str(e)}', 'error')
        return redirect(url_for('view_report', scan_id=scan_id))


@app.route('/api/analysis/<scan_id>')
def get_analysis_data(scan_id):
    # Basic validation
    try:
        uuid.UUID(scan_id, version=4)
    except ValueError:
        return jsonify({"error": "Invalid Scan ID format"}), 400

    filepath = os.path.join(RESULTS_DIR, f"{scan_id}.json")
    if not os.path.exists(filepath):
        return jsonify({"error": "Analysis not found"}), 404

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        # Optional sort/format for API consistency if needed
        # data = format_reused_passwords(data)
        # data = sort_password_analysis(data)
        return jsonify(data)
    except Exception as e:
        app.logger.error(f"API Error for {scan_id}: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=app.config["DEBUG"])
