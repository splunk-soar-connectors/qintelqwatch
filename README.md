# Qintel QWatch

Publisher: Qintel, LLC \
Connector Version: 1.0.1 \
Product Vendor: Qintel \
Product Name: Qintel QWatch \
Minimum Product Version: 5.0.0

This app retrieves exposed credential alerts from Qintel's QWatch platform

### Configuration variables

This table lists the configuration variables required to operate Qintel QWatch. These variables are specified when configuring a Qintel QWatch asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**client_id** | required | string | Client ID |
**client_secret** | required | password | Client Secret |
**remote** | optional | string | QWatch API URL (Optional) |
**qwatch_fetch_password** | optional | boolean | Fetch plaintext passwords |
**qwatch_initial_window** | optional | numeric | QWatch Initial Ingestion Window (Days) |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration \
[on poll](#action-on-poll) - Generate events and artifacts from QWatch alerts \
[search qwatch exposures](#action-search-qwatch-exposures) - Queries QWatch for credential exposures

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'on poll'

Generate events and artifacts from QWatch alerts

Type: **ingest** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | optional | Start of time range, in epoch time (milliseconds) | numeric | |
**end_time** | optional | End of time range, in epoch time (milliseconds) | numeric | |
**container_count** | optional | Maximum number of container records to query for | numeric | |
**artifact_count** | optional | Maximum number of artifact records to query for | numeric | |

#### Action Output

No Output

## action: 'search qwatch exposures'

Queries QWatch for credential exposures

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** | optional | Email to query | string | `qwatch credential` `email` |
**domain** | optional | Domain to query | string | `domain` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.domain | string | `domain` | |
action_result.parameter.email | string | `qwatch credential` `email` | |
action_result.data.\*.credential | string | `qwatch credential` `email` | info@example.local |
action_result.data.\*.first_seen | string | | |
action_result.data.\*.last_seen | string | | |
action_result.data.\*.password | password | `qwatch password` | |
action_result.data.\*.source_name | string | `qwatch source name` | |
action_result.status | string | | success failed |
action_result.summary.exposure_count | numeric | | |
action_result.summary | numeric | | |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
