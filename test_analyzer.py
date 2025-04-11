import json
import os
import uuid
from analyzer import perform_analysis as perform_bitwarden_analysis
from flask_caching import Cache

mock_cache = Cache(config={'CACHE_TYPE': 'SimpleCache'})

RESULTS_DIR_TEST = 'test_analysis_output'
if not os.path.exists(RESULTS_DIR_TEST):
    os.makedirs(RESULTS_DIR_TEST)

TEST_SETTINGS = {
  "password_age_years": 1,
  "check_hibp": True,
  "analyze_notes_fields": True,
  "common_passwords_file": None
}


def run_test(input_filename, scan_id_prefix):
    try:
        with open(input_filename, 'r', encoding='utf-8') as f:
            bitwarden_data = json.load(f)

        scan_id = f"{scan_id_prefix}-{str(uuid.uuid4())[:8]}"
        print(f"--- Running analysis for {input_filename} "
              f"with Scan ID: {scan_id} ---")

        results_dict = perform_bitwarden_analysis(
            bitwarden_data=bitwarden_data,
            scan_id=scan_id,
            results_dir=RESULTS_DIR_TEST,
            settings=TEST_SETTINGS,
            cache=mock_cache
        )

        output_filepath = os.path.join(RESULTS_DIR_TEST, f"{scan_id}.json")
        print(f"Analysis complete. Results saved to: {output_filepath}")

        if results_dict and 'summary' in results_dict:
            print("\nSummary:")
            print(json.dumps(results_dict['summary'], indent=2))
        if results_dict and 'findings' in results_dict:
            print("\nKey Findings:")
            print(json.dumps(results_dict['findings'], indent=2))
        if results_dict and 'details' in results_dict:
            reused_groups = results_dict['details'].get('reused_passwords', [])
            reused_count = len(reused_groups)
            print(f"\nReused Password Groups Found: {reused_count}")
            if reused_count > 0:
                largest_reuse = max(reused_groups, key=lambda x: x['count'],
                                    default=None)
                if largest_reuse:
                    print(f"Largest reuse group has {largest_reuse['count']} items.") # noqa E501
            pwned_count = len(results_dict['details'].get('pwned_passwords', [])) # noqa E501
            print(f"Pwned Passwords Found: {pwned_count}")
            insecure_uris_count = len(results_dict['details'].get('insecure_uris', [])) # noqa E501
            print(f"Insecure URIs Found: {insecure_uris_count}")
            old_pass_count = len(results_dict['details'].get('old_passwords', [])) # noqa E501
            print(f"Old Passwords Found: {old_pass_count}")
            secrets_notes = len(results_dict['details'].get('secrets_in_notes', [])) # noqa E501
            print(f"Secrets in Notes Found: {secrets_notes}")
            secrets_fields = len(results_dict['details'].get('secrets_in_fields', [])) # noqa E501
            print(f"Secrets in Fields Found: {secrets_fields}")

    except FileNotFoundError:
        print(f"Error: Input file {input_filename} not found.")
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in {input_filename}.")
    except Exception as e:
        print(f"An error occurred during analysis of {input_filename}: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    run_test('exemplo-bitwarden.json', 'exemplo')
    print("\n" + "="*40 + "\n")
    run_test('bitwarden-export.json', 'export')
