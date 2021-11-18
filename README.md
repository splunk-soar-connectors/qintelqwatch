# Qintel QWatch App for Splunk SOAR

## Description

Qintel's QWatch system contains credentials obtained from dump sites, hacker collaboratives, and command
and control infrastructures of eCrime- and APT-related malware. With this integration, users can fetch
exposure alerts as events and discover exposed credentials associated with their organization.


For more information, existing customers can visit our
[Integrations Documentation](https://docs.qintel.com/integrations/overview).

## Actions

### search qwatch exposures

Queries QWatch for credential exposures by email or domain. Returns a list of exposures containing the
following elements:

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

_Sales:_ contactus@qintel.com

_Support:_ integrations-support@qintel.com

## Legal and License

This Phantom App is licensed under the Apache 2.0 license.
