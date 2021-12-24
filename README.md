[comment]: # "  Copyright (c) 2009-2021 Qintel, LLC"
[comment]: # ""
[comment]: # "  Licensed under the Apache License, Version 2.0 (the \"License\");"
[comment]: # "  you may not use this file except in compliance with the License."
[comment]: # "  You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "      http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "  Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "  the License is distributed on an \"AS IS\" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "  either express or implied. See the License for the specific language governing permissions"
[comment]: # "  and limitations under the License."
[comment]: # ""
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

**Port Information**
*  The app uses HTTP/ HTTPS protocol for communicating with the Qintel QWatch server. Below are the default ports used by the Splunk SOAR Connector.

    SERVICE NAME | TRANSPORT PROTOCOL | PORT
    ------------ | ------------------ | ----
    http | tcp | 80
    https | tcp | 443
