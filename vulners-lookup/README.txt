Version 0.0.5

-------------------------------------------------------------------------------
Application support
-------------------------------------------------------------------------------

This is an open source project, public repository available at https://github.com/vulnersCom/splunk-vulners.
Direct support is available at support@vulners.com

-------------------------------------------------------------------------------
Description
-------------------------------------------------------------------------------

This application makes use of Vulners Com API to audit packages installed on the hosts.
The application consists of two parts - a custom command script to be installed on the search-head
and a packages collecting script to be installed on the indexers and endpoint servers via universal forwarder.
The custom command script makes requests to the external API endpoint at
https://<vulners endpoint>/api/v3/audit/audit/ with a aggregated list of found packages and their versions.
It it possible to use own Vulners Proxy endpoint instead of Vulners.com host.
For this you should set proper Vulners endpoint during application setup phase.
The results of custom command are stored in a local lookup csv with vulners.csv name.
The resulting csv lookup file is later used in the dashboard to provide general
overview of vulnerabilities found per host as well as provide links to vulners.com for further reading.
The forwarder script is largely based on the source code of Vulners Com agent
(https://github.com/vulnersCom/vulners-agent), so for now it only works with *nix OS.

It is also possible to use alternative methods of software packages data collecting instead of python scripted input.
For example, you can preconfigured queries for osquery security agent.

RPM Packages:
SELECT (SELECT REPLACE(value, '"','') FROM augeas where path='/etc/os-release' and label='ID') as osname, (SELECT REPLACE(value, '"','') FROM augeas where path='/etc/os-release' and label='VERSION_ID') as osversion, name || '-' || version || '-' || release || '-' || arch as package FROM rpm_packages
DEB Packages:
SELECT (SELECT REPLACE(value, '"','') FROM augeas where path='/etc/os-release' and label='ID') as osname, (SELECT REPLACE(value, '"','') FROM augeas where path='/etc/os-release' and label='VERSION_ID') as osversion, name || ' ' || version || ' ' || arch as package FROM deb_packages

-------------------------------------------------------------------------------
Installation
-------------------------------------------------------------------------------

To use the app you need to install app itself on search head (or search head cluster), indexers (or indexer cluster) 
and optionally on forwarders (if you want to use python scripted input for software packages data collection).
By default forawarders will collect data to 'vulners', this index also used by vulners_report saved search (disabled by default).
So you previously need to create 'vulners' index on your indexers (or indexer cluster) or set another index in the configuration files.

1) Installation on search head

- Web Interface:
-------------------------------------------------------------------------------
Log into Splunk with an administrator account.
Go into Application Management section.
Click on the "Install app from file" button.
Click the "Choose File" button and browse to the location on your local machine
where the .tgz archive with app is located and select it.
Check the "Upgrade App" checkbox to overwrite any previous versions of this app
Click the "Upload button"

- Shell:
-------------------------------------------------------------------------------
Log into the shell for your Splunk server
Change to the Splunk application folder:
  cd $SPLUNK_HOME/etc/apps
Extract the application from the archive file:
  tar xzf <archive location>
Verify that the app has the proper permissions for the OS:
  chown -R splunk:splunk $SPLUNK_HOME/etc/apps/vulners-lookup
Restart Splunk
  $SPLUNK_HOME/bin/splunk restart

- Install on search head cluster:
-------------------------------------------------------------------------------
Use installation via deployer scheme described on
 https://docs.splunk.com/Documentation/AddOns/released/Overview/Distributedinstall


2) Create "vulners" index on indexers

- Index install on single indexer
-------------------------------------------------------------------------------
Log into Splunk with an administrator account.
Click the "Settings" button and choose "Indexes"
Click "New index" button
Specify "vulners" as the "Index Name"
Choose "Vulners Dashboard for Splunk" in the "App" drop-down menu
Fill the rest of the fields accordingly

- Index install on indexer cluster
-------------------------------------------------------------------------------
Use installation via manager node scheme described on
 https://docs.splunk.com/Documentation/AddOns/released/Overview/Distributedinstall


3) Installation on universal forwarder

- Single Universal Forwarder
-------------------------------------------------------------------------------
Log into the shell for your SplunkForwarder server
Change to the SplunkForwarder application folder:
  cd $SPLUNK_HOME/etc/apps
Extract the application from the archive file:
  tar -xzf <archive location>
Enable scripted input in inputs.conf
  Set disabled = 0
Verify that the app has the proper permissions for the OS:
  chown -R splunk:splunk $SPLUNK_HOME/etc/apps/vulners-lookup
Restart Splunk
  $SPLUNK_HOME/bin/splunk restart

- Multiple Universal Forwarders via Deployment Server
-------------------------------------------------------------------------------
Use installation via deployment server scheme described on
 https://docs.splunk.com/Documentation/AddOns/released/Overview/Distributedinstall

-------------------------------------------------------------------------------
Configuration:
-------------------------------------------------------------------------------

The Vulners App for Splunk application has a simple configuration interface.
Before starting configuration of the application, you must have your Vulners API key.
You can obtain one from https://vulners.com/api-keys. You will be asked for it at the first app launch.
You can change it any time by reconfiguring application from "Manage Apps" section.
You can also set your custom Vulners Proxy endpoint in setup page.

By default forwarder is set to run task to collect packages every 3000 seconds (60 minutes).
To change that create file
$SPLUNK_HOME/etc/apps/vulners-lookup/local/inputs.conf
based on
$SPLUNK_HOME/etc/apps/vulners-lookup/default/inputs.conf
