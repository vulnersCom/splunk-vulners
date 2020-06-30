Version 0.0.1

Application support:
This is an open source project, no direct support provided, public repository available at https://github.com/vulnersCom/splunk-vulners.

Description
This application makes use of Vulners Com API to audit packages installed on the hosts. The application consists of two parts - a lookup script to be installed on the search-head and a collecting scri
pt to be installed on the universal forwarder.
The lookup script makes requests to the external API endpoint at https://vulners.com/api/v3/audit/audit/ with a list of found packages and their versions. For each found vulnerability the script then
 uses the results to provide links to vulners com website for further reading.
The forwarder script is largely based on the source code of Vulners Com agent (https://github.com/vulnersCom/vulners-agent), so for now it only works with *nix OS.

Additional requirements
- Set up vulners index please as forwarder depends on it and stores found data there.
- Set up additional summary index *vulnersresults*
- Set up a scheduled search:
```
index=vulners | lookup vulnerslook os version package output os as osname version as osversion cve as vulnId | eval score="1", ip="10.0.0.1", title="qwerty", severityText="high" | rename host as extracted_host | stats count by severityText ip extracted_host osname osversion package title vulnId score | collect
```
as per https://docs.splunk.com/Documentation/Splunk/8.0.4/Knowledge/Usesummaryindexing to save the results in the summary index *vulnersresults*
