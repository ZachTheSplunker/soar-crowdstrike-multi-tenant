# Splunk SOAR - Crowdstrike Multi-Tenant

Playbooks and custom functions to integrate with multiple tenants in Crowdstrike.

## Overview

1. Add tenant CIDs and names to custom list
1. Configure assets to match names associated with CIDs
1. Sit back and enjoy the automation.


## Configure List

This process utilizes a custom list to map tenant CIDs to their name. The asset name will need to **exactly match** the name in the list. Spaces are allowed.

```
i.e.

938225876388027c43188572285c4e8d2l1z, parent tenant
196225876388027c43188572285c4e8d7f8m, tenant one
196229573988027c43188572285c4e8d3w6q, tenant one
```


## Configure Assets

Only the parent tenant needs to be configured to poll data from Crowdstrike. The other tenants can just be configured with API credentials. The important thing is to **exactly match** the asset name to the custom list name.

By default the included playbooks use the "crowdstrike" or "event" labels. Customize if needed.