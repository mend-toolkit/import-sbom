[![Logo](https://resources.mend.io/mend-sig/logo/mend-dark-logo-horizontal.png)](https://www.mend.io/)

[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://github.com/mend-toolkit/import-sbom/actions/workflows/ci.yml/badge.svg)](https://github.com/mend-toolkit/import-sbom/actions/workflows/ci.yml/badge.svg)
[![GitHub release](https://img.shields.io/github/v/release/mend-toolkit/import-sbom)](https://github.com/mend-toolkit/import-sbom/releases/latest)

# Import SBOM

A CLI tool that imports a project inventory into Mend from a SBOM report in the [SPDX](https://spdx.org) format or CSV format.

The tool can either upload data directly to Mend, or alternatively, create a Mend Offline Request file that can be uploaded separately using one of the following methods:
- Using the Mend Unified Agent (see [Uploading an Offline Request File](https://docs.mend.io/bundle/unified_agent/page/scanning_with_the_unified_agent_in_offline_mode.html#Uploading-an-Offline-Request-File))
- Via Mend's UI (**Admin** >> **Upload Update Request**)
- Using Mend's API (see [Uploading Update Requests via the Mend API](https://docs.mend.io/bundle/wsk/page/uploading_update_requests_via_the_mend_api.html))

The tool supports input files in either **JSON** or **CSV** formats.
<hr>

- [Import SBOM](#import-sbom)
  - [Supported Operating Systems](#supported-operating-systems)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Importing SPDX SBOM (JSON)](#importing-spdx-sbom-json)
    - [Imported File Structure](#imported-file-structure)
    - [Execution Examples](#execution-examples)
  - [Importing CSV SBOM](#importing-csv-sbom)
    - [Imported File Structure](#imported-file-structure-1)
    - [Execution Examples](#execution-examples-1)

<hr>

## Supported Operating Systems
- **Linux (Bash):**	CentOS, Debian, Ubuntu
- **Windows (PowerShell):**	10, 2012, 2016

## Prerequisites
- Python 3.9+
- Mend user with admin permissions

## Installation
```shell
pip install mend-import-sbom
```
> **Note:** Depending on whether the package was installed as a root user or not, you need to make sure the package installation location was added to the `$PATH` environment variable.

## Usage
**Using command-line arguments only:**
```shell
import_sbom --user-key $WS_USERKEY --api-key $WS_APIKEY --url $WS_WSS_URL --input $SBOM_FILE_PATH --scope "ProductName//ProjectName" --dir $OUTPUT_DIRECTORY
```
**Using environment variables:**
```shell
export WS_USERKEY=xxxxxxxxxxx
export WS_APIKEY=xxxxxxxxxxx
export WS_WSS_URL=https://saas.mend.io

import_sbom --input $SBOM_FILE_PATH --scope "ProductName//ProjectName"
```
> **Note:** Either form is accepted. For the rest of the examples, the latter form would be used

## Configuration Parameters
>**Note:** Parameters can be specified as either command-line arguments, environment variables, or a combination of both.
>
> Command-line arguments take precedence over environment variables.

| CLI argument                      | Env. Variable          |   Type   | Required | Description                                                                                                                                                                                       |
|:----------------------------------|:-----------------------|:--------:|:--------:|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **&#x2011;&#x2011;help**          |                        | `switch` |    No    | Show help and exit                                                                                                                                                                                |
| **&#x2011;&#x2011;version**       |                        | `switch` |    No    | Show current version and exit                                                                                                                                                                     || **&#x2011;&#x2011;user-key**      | `WS_USERKEY`           | `string` |   Yes    | Mend User Key                                                                            |
| **&#x2011;&#x2011;api-key**       | `WS_APIKEY`            | `string` |   Yes    | Mend API Key                                                                                                                                                                                      |
| **&#x2011;&#x2011;url**           | `WS_WSS_URL`           | `string` |   Yes    | Mend Server URL                                                                                                                                                                                   |
| **&#x2011;&#x2011;input**         | `SBOM`                 | `string` |   Yes    | SBOM report file to import (`*.json` or `*.csv`)                                                                                                                                                  |
| **&#x2011;&#x2011;scope**         | `WS_SCOPE`             | `string` |   No*    | Product and Project names to create/update. Expected format: `"PRODUCT//PROJECT"`                                                                                                                 |
| **&#x2011;&#x2011;updateType**    | `WS_UPDATETYPE`        | `string` |    No    | APPEND or OVERRIDE results when importing into an existing project (default: `OVERRIDE`)                                                                                                          |
| **&#x2011;&#x2011;dir**           |                        | `string` |    No    | Output directory for the `update-request.txt` file** in Offline mode (default: `$PWD`)                                                                                                            |
| **&#x2011;&#x2011;offline**       | `WS_OFFLINE`           |  `bool`  |    No    | Create offline update request file without uploading to Mend (default: `false`)                                                                                                                   |
| **&#x2011;&#x2011;multilang**     | `WS_MULTILANG`         |  `bool`  |   No**   | In case no SHA1 searching library by All known package types (default: `true`)                                                                                                                    |
| **&#x2011;&#x2011;proxy**         | `HTTP_PROXY`           | `string` |    No    | Proxy host including port, with or without protocol prefix and optionally credentials. Expected formats:myproxy.host.com:1234,http://myproxy.host.com:1234,http://user:pass@myproxy.host.com:1234 |
| **&#x2011;&#x2011;proxyUsername** | `HTTP_PROXY_USERNAME`  | `string` |    No    | Proxy username, if needed and if not included in the proxy host.                                                                                                                                  |
| **&#x2011;&#x2011;proxyPassword** | `HTTP_PROXY_PASSWORD`  | `string` |    No    | Proxy password, if needed and if not included in the proxy host.                                                                                                                                  |


> \* `--scope` specifies the hierarchy (full or partial) for uploading the SBOM report using product and project identifiers.
> Both the product and project can be identified by either names (for creating a new one) or token (for updating an existing one).
>
> * `--scope "ProductName//ProjectName"` would specify both the product name and project name to create/update.
> * `--scope "ProjectName"` would specify only the project name, and the product name would default to `Mend-Imports`.
> * `--scope "ProjectToken"` would specify the token of an existing project, and the product name would default to that project's parent product. When specifying a project token, you cannot specify a product name/token.
> * If `--scope` isn't specified, the project name will be taken from the SBOM's `name` property (for `*.json` SPDX) or its parent directory (for `*.csv`).
>
> ** See more details about the [update-request.txt](https://docs.mend.io/bundle/wsk/page/does_mend_have_the_ability_to_scan_when_offline_and_then_upload_the_scan_results_when_online_.html) file and [Offline mode](https://docs.mend.io/csh?context=2524153159&topicname=unified_agent_-_advanced_topics.html#Scanning-in-Offline-Mode)  in Mend's documentation.

> \** If `--multilang` is False script will try to find relevant package name in the Creator field. If such a candidate is found just it will be used for searching libraries.

## Importing SPDX SBOM (JSON)

### Imported File Structure
The SPDX document must correspond to the [Composition of an SPDX document](https://spdx.github.io/spdx-spec/v2.3/composition-of-an-SPDX-document) specification.

The following table describes the set of properties for each imported library:

| Property                 | Required | Description                                                                                                              |
|:-------------------------|:--------:|:-------------------------------------------------------------------------------------------------------------------------|
| **name**                 |    No    | [File Name](https://spdx.github.io/spdx-spec/v2.3/file-information/#81-file-name-field)                                  |
| **downloadLocation**     |    No    | [Download Location](https://spdx.github.io/spdx-spec/v2.3/package-information/#77-package-download-location-field)       |
| **licenseConcluded**     |    No    | [License Concluded](https://spdx.github.io/spdx-spec/v2.3/package-information/#713-concluded-license-field)              |
| **licenseInfoFromFiles** |    No    | [License Info](https://spdx.github.io/spdx-spec/v2.3/package-information/#714-all-licenses-information-from-files-field) |
| **licenseDeclared**      |    No    | [License Declared](https://spdx.github.io/spdx-spec/v2.3/package-information/#715-declared-license-field)                |
| **copyrightText**        |    No    | [Copyright Text](https://spdx.github.io/spdx-spec/v2.3/package-information/#717-copyright-text-field)                    |
| **versionInfo**          |   Yes*   | [Version Info](https://spdx.github.io/spdx-spec/v2.3/package-information/#73-package-version-field)                      |
| **packageFileName**      |   Yes*   | [Package Name](https://spdx.github.io/spdx-spec/v2.3/package-information/#74-package-file-name-field)                    |
| **supplier**             |    No    | [Supplier](https://spdx.github.io/spdx-spec/v2.3/package-information/#75-package-supplier-field)                         |
| **originator**           |    No    | [Originator](https://spdx.github.io/spdx-spec/v2.3/package-information/#76-package-originator-field)                     |
| **sha1**                 |   Yes*   | [SHA1](https://spdx.github.io/spdx-spec/v2.3/package-information/#710-package-checksum-field)                            |
| **homepage**             |    No    | [Home Page](https://spdx.github.io/spdx-spec/v2.3/package-information/#711-package-home-page-field)                      |

> \* Each library requires either **sha1** or the **packageFileName** and **versionInfo** pair.
>
>    **Note:** If **sha1** isn't provided for a particular library, the tool will attempt to search that library by its name and version in Mend's index, which will result in longer execution times.

### Execution Examples

> **Note:** In the following examples, $WS_USERKEY, $WS_APIKEY and $WS_WSS_URL are assumed to have been exported as environment variables.

Import SPDX SBOM into a new Mend project

```shell
import_sbom --scope "$WS_PRODUCTNAME//$WS_PROJECTNAME" --dir $HOME/reports --input $HOME/reports/$WS_PROJECTNAME-sbom.json
```

Convert SPDX SBOM to an [offline update request](https://docs.mend.io/bundle/wsk/page/understanding_update_requests.html) file for creating a new Mend project under a specific product

```shell
import_sbom --scope "$WS_PRODUCTNAME//$WS_PROJECTNAME" --dir $HOME/reports --input $HOME/reports/my-project-sbom.json --offline True
```

Convert SPDX SBOM to an [offline update request](https://docs.mend.io/bundle/wsk/page/understanding_update_requests.html) file for overriding an existing Mend project

```shell
import_sbom --scope "$WS_PRODUCTNAME//$WS_PROJECTNAME" --dir $HOME/reports --input $HOME/reports/my-project-sbom.json --offline True

import_sbom --scope $WS_PROJECTTOKEN --dir $HOME/reports --input $HOME/reports/my-project-sbom.json --offline True
```

Convert SPDX SBOM to an [offline update request](https://docs.mend.io/bundle/wsk/page/understanding_update_requests.html) file for appending to an existing Mend project

```shell
import_sbom --scope "$WS_PRODUCTNAME//$WS_PROJECTNAME" --dir $HOME/reports --input $HOME/reports/my-project-sbom.json --offline True --updateType APPEND

import_sbom --scope $WS_PROJECTTOKEN --dir $HOME/reports --input $HOME/reports/my-project-sbom.json --offline True --updateType APPEND
```

## Importing CSV SBOM

### Imported File Structure

[Download CSV Template](./templates/import_template.csv)

| Header               | Required | Reference                                                                                                                |
|:---------------------|:---------|:-------------------------------------------------------------------------------------------------------------------------|
| name                 | No       | [File Name](https://spdx.github.io/spdx-spec/v2.3/file-information/#81-file-name-field)                                  |
| downloadLocation     | No       | [Download Location](https://spdx.github.io/spdx-spec/v2.3/package-information/#77-package-download-location-field)       |
| licenseConcluded     | No       | [License Concluded](https://spdx.github.io/spdx-spec/v2.3/package-information/#713-concluded-license-field)              |
| licenseInfoFromFiles | No       | [License Info](https://spdx.github.io/spdx-spec/v2.3/package-information/#714-all-licenses-information-from-files-field) |
| licenseDeclared      | No       | [License Declared](https://spdx.github.io/spdx-spec/v2.3/package-information/#715-declared-license-field)                |
| copyrightText        | No       | [Copyright Text](https://spdx.github.io/spdx-spec/v2.3/package-information/#717-copyright-text-field)                    |
| versionInfo          | Yes*     | [Version Info](https://spdx.github.io/spdx-spec/v2.3/package-information/#73-package-version-field)                      |
| packageFileName      | Yes*     | [Package Name](https://spdx.github.io/spdx-spec/v2.3/package-information/#74-package-file-name-field)                    |
| supplier             | No       | [Supplier](https://spdx.github.io/spdx-spec/v2.3/package-information/#75-package-supplier-field)                         |
| originator           | No       | [Originator](https://spdx.github.io/spdx-spec/v2.3/package-information/#76-package-originator-field)                     |
| sha1                 | Yes*     | [SHA1](https://spdx.github.io/spdx-spec/v2.3/package-information/#710-package-checksum-field)                            |
| homepage             | No       | [Home Page](https://spdx.github.io/spdx-spec/v2.3/package-information/#711-package-home-page-field)                      |

> \* Each library requires either **sha1** or the **packageFileName** and **versionInfo** pair. Other fields can remain empty.
>
>    **Note:** If **sha1** isn't provided for a particular library, the tool will attempt to search that library by its name and version in Mend's index, which will result in longer execution times.

### Execution Examples

> **Note:** In the following examples, $WS_USERKEY, $WS_APIKEY and $WS_WSS_URL are assumed to have been exported as environment variables.

Import CSV SBOM into a new Mend project under the default product (`Mend-Imports`)

```shell
import_sbom --scope "$WS_PROJECTNAME" --dir $HOME/reports --input $HOME/reports/$WS_PROJECTNAME.csv
```

Import CSV SBOM, appending to an existing Mend project

```shell
import_sbom --scope "$WS_PRODUCTNAME//$WS_PROJECTNAME" --dir $HOME/reports --input $HOME/reports/$WS_PROJECTNAME.csv --updateType APPEND

import_sbom --scope $WS_PROJECTTOKEN --dir $HOME/reports --input $HOME/reports/$WS_PROJECTNAME.csv --updateType APPEND
```
