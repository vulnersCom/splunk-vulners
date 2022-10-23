Version 0.0.5

-------------------------------------------------------------------------------
Application support
-------------------------------------------------------------------------------

This is an open source project, public repository available at https://github.com/vulnersCom/splunk-vulners.
Direct support is available at support@vulners.com

-------------------------------------------------------------------------------
Description
-------------------------------------------------------------------------------

This application makes use of Vulners Com API to audit software packages installed on the hosts.
The application consists of two parts - a custom command script to be installed on the search-head
and a packages collecting script to be installed on the indexers and endpoint servers via universal forwarder.
The custom command script makes requests to the external API endpoint at
https://<vulners endpoint>/api/v3/audit/audit/ with a aggregated list of found packages and their versions.
It it possible to use your own Vulners Proxy (https://github.com/vulnersCom/vulners-proxy) endpoint instead of Vulners.com host.
For this you should set proper Vulners endpoint during application setup phase.
The results of custom command are stored in a local lookup csv with vulners.csv name.
The resulting csv lookup file is later used in the set of dashboards to provide general
overview of vulnerabilities found per host as well as provide links to vulners.com for further reading.
The forwarder script is largely based on the source code of Vulners.com agent
(https://github.com/vulnersCom/vulners-agent), so for now it only works with *nix OS.

It is also possible to use alternative methods of software packages data collecting instead of python scripted input.
For example, you can use the Osquery (https://osquery.io/) security agent queries.

RPM Packages:
SELECT (SELECT REPLACE(value, '"','') FROM augeas where path='/etc/os-release' and label='ID') as osname, (SELECT REPLACE(value, '"','') FROM augeas where path='/etc/os-release' and label='VERSION_ID') as osversion, name || '-' || version || '-' || release || '-' || arch as package FROM rpm_packages
DEB Packages:
SELECT (SELECT REPLACE(value, '"','') FROM augeas where path='/etc/os-release' and label='ID') as osname, (SELECT REPLACE(value, '"','') FROM augeas where path='/etc/os-release' and label='VERSION_ID') as osversion, name || ' ' || version || ' ' || arch as package FROM deb_packages

-------------------------------------------------------------------------------
Installation
-------------------------------------------------------------------------------

To use the app you need to install app itself on search head (or search head cluster) and optionally on forwarders (if you want to use python scripted input for software packages data collection) and indexers (or indexer cluster) for proper parsing of forwarded packages.
If you don't plan to use python scripted input for data collectinon you will need to install the app only on search head (search head cluster).
By default forwarders will collect data to 'vulners' index, this index also used by 'vulners_report' saved search (disabled by default).
So you must create 'vulners' index on your indexers (or indexer cluster) or set another index in the corresponding configuration files befoure you start packages collection.



1) Install the app on search head

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

- Installation on search head cluster:
-------------------------------------------------------------------------------
Use installation scheme via deployer described on
https://docs.splunk.com/Documentation/AddOns/released/Overview/Distributedinstall

After that you can enable 'vulners_report' saved search to create schedule-based vulners.csv lookup creation



2) Create "vulners" index on indexers

- Index install on single indexer
-------------------------------------------------------------------------------
Log into Splunk with an administrator account.
Click the "Settings" button and choose "Indexes"
Click "New index" button
Specify "vulners" as the "Index Name"
Choose "Vulners Dashboard for Splunk" in the "App" drop-down menu
Fill the rest of the fields accordingly

- Index on indexer cluster
-------------------------------------------------------------------------------
Use installation scheme via manager node described on
https://docs.splunk.com/Documentation/AddOns/released/Overview/Distributedinstall



3) Install the app on indexers

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

- Installation on indexer cluster
-------------------------------------------------------------------------------
Use installation scheme via manager node described on
https://docs.splunk.com/Documentation/AddOns/released/Overview/Distributedinstall



4) Installation on universal forwarder

- Installaion on single Universal Forwarder
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

- Install on multiple Universal Forwarders using Deployment Server
-------------------------------------------------------------------------------
Use installation via deployment server scheme described on
 https://docs.splunk.com/Documentation/AddOns/released/Overview/Distributedinstall
 
 Whether you are using a deployment server or not, you must enable scripted input to collect packages from servers.
 

-------------------------------------------------------------------------------
Configuration:
-------------------------------------------------------------------------------

The Vulners App for Splunk application has a simple configuration interface.
Before starting configuration of the application, you must have your Vulners API key.
You can obtain one from https://vulners.com/api-keys. You will be asked for it at the first app launch.
You can change it any time by reconfiguring application from "Manage Apps" section.
You can also set your custom Vulners Proxy endpoint in setup page at the first app launch.

By default forwarder is set to run task to collect packages every 3000 seconds (60 minutes).
To change that create file
$SPLUNK_HOME/etc/apps/vulners-lookup/local/inputs.conf
based on
$SPLUNK_HOME/etc/apps/vulners-lookup/default/inputs.conf
