# Qintel QWatch

Publisher: Qintel, LLC\
Connector Version: 1.0.1\
Product Vendor: Qintel\
Product Name: Qintel QWatch\
Product Version Supported (regex): ".\*"\
Minimum Product Version: 5.0.0

This app retrieves exposed credential alerts from Qintel's QWatch platform

# Qintel QWatch App for Splunk SOAR

## Description

Qintel's QWatch system contains credentials obtained from dump sites, hacker collaboratives, and
command and control infrastructures of eCrime- and APT-related malware. With this integration, users
can fetch exposure alerts as events and discover exposed credentials associated with their
organization.

For more information, existing customers can visit our [Integrations
Documentation](https://docs.qintel.com/integrations/overview)

## Actions

### search qwatch exposures

Queries QWatch for credential exposures by email or domain. Returns a list of exposures containing
the following elements:

- Username
- Plaintext Password (optional)
- Exposure Source Name
- Credential First Seen Timestamp
- Credential Last Seen Timestamp

### on poll

Generates events and artifacts from QWatch exposure alerts. Each artifact is created with the
following elements:

- Username
- Plaintext Password (optional)
- Username First Seen Timestamp
- Username Last Seen Timestamp
- Credential First Seen Timestamp
- Credential Last Seen Timestamp

### test connectivity

Test connectivity to the QWatch API

## Contact Information

*Sales:* contactus@qintel.com\
*Support:* integrations-support@qintel.com

## Legal and License

This Phantom App is licensed under the Apache 2.0 license.

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Qintel QWatch server. Below are the
default ports used by the Splunk SOAR Connector.

| SERVICE NAME | TRANSPORT PROTOCOL | PORT |
|--------------|--------------------|------|
| http | tcp | 80 |
| https | tcp | 443 |

### Configuration Variables

The below configuration variables are required for this Connector to operate. These variables are specified when configuring a Qintel QWatch asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**client_id** | required | string | Client ID
**client_secret** | required | password | Client Secret
**remote** | optional | string | QWatch API URL (Optional)
**ph2** | optional | ph |
**qwatch_fetch_password** | optional | boolean | Fetch plaintext passwords
**qwatch_initial_window** | optional | numeric | QWatch Initial Ingestion Window (Days)

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration\
[on poll](#action-on-poll) - Generate events and artifacts from QWatch alerts\
[search qwatch exposures](#action-search-qwatch-exposures) - Queries QWatch for credential exposures

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test**\
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'on poll'

Generate events and artifacts from QWatch alerts

Type: **ingest**\
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | optional | Start of time range, in epoch time (milliseconds) | numeric |
**end_time** | optional | End of time range, in epoch time (milliseconds) | numeric |
**container_count** | optional | Maximum number of container records to query for | numeric |
**artifact_count** | optional | Maximum number of artifact records to query for | numeric |

#### Action Output

No Output

## action: 'search qwatch exposures'

Queries QWatch for credential exposures

Type: **investigate**\
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** | optional | Email to query | string | `qwatch credential` `email`
**domain** | optional | Domain to query | string | `domain`

#### Action Output

DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action_result.parameter.domain | string | `domain`
action_result.parameter.email | string | `qwatch credential` `email`
action_result.data.\*.credential | string | `qwatch credential` `email`
action_result.data.\*.first_seen | string |
action_result.data.\*.last_seen | string |
action_result.data.\*.password | password | `qwatch password`
action_result.data.\*.source_name | string | `qwatch source name`
action_result.status | string |
action_result.summary.exposure_count | numeric |
action_result.summary | numeric |
action_result.message | string |
summary.total_objects | numeric |
summary.total_objects_successful | numeric |
