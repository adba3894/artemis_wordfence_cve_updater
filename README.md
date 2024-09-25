**WordPress Vulnerability CVE Enrichment Script for Artemis Scans**

This Python script is dedicated to adding CVE (Common Vulnerabilities and Exposures) codes for WordPress vulnerabilities detected during vulnerability scans performed by Artemis. The script automatically enhances Artemis scan results by retrieving detailed vulnerability information from the Wordfence API and updating the original JSON output with relevant CVE data.

**How It Works:**

1. Parse Artemis Scan Output:
The script starts by loading and parsing the Artemis scan results, specifically focusing on additional_data objects to find the slug values, which represent the WordPress plugins.

2. Retrieve Vulnerability Information from https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production

3. Match Vulnerabilities to Plugin Version:
The script compares the vulnerabilities returned by Wordfence with the WordPress plugin version identified in the Artemis scan results. For matching versions, it extracts the associated CVE codes.

4. Update Artemis Scan Results:
The script creates a new cves object and appends it to the relevant section of the Artemis scan data, linking the CVE codes to the specific vulnerabilities.

5. Save Updated JSON File:
After enriching the Artemis scan results with CVE information, the script updates the JSON file, preserving the original data structure while adding the CVE codes.

The script will output an updated version of the Artemis scan file, enriched with CVE codes, at the same location or a specified path.

**API Reference:**

Wordfence Vulnerability Intelligence API: https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production
