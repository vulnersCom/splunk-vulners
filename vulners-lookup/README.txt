Version 0.0.2

-------------------------------------------------------------------------------
Application support
-------------------------------------------------------------------------------

This is an open source project, public repository available at https://github.com/vulnersCom/splunk-vulners.
Direct support is available at support@vulners.com

-------------------------------------------------------------------------------
Description
-------------------------------------------------------------------------------

This application makes use of Vulners Com API to audit packages installed on the hosts.
The application consists of two parts - a lookup script to be installed on the search-head
and a collecting script to be installed on the universal forwarder.
The lookup script makes requests to the external API endpoint at
https://vulners.com/api/v3/audit/audit/ with a list of found packages and their versions.
The results are stored in a local lookup csv.
The resulting csv lookup file is later used in the dashboard to provide general
overview of vulnerabilities found per host as well as provide links to vulners.com
for further reading.
The forwarder script is largely based on the source code of Vulners Com agent
(https://github.com/vulnersCom/vulners-agent), so for now it only works with *nix OS.

-------------------------------------------------------------------------------
Installation
-------------------------------------------------------------------------------

To use the app you need to install app itself on search_head and forwarders and
set up 'vulners' index as forwarder app depends on it and stores found data there.

You can also watch a short video about installation process here - https://vimeo.com/440607980


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
-------------------------------------------------------------------------------

2) Create "vulners" index
-------------------------------------------------------------------------------
Log into Splunk with an administrator account.
Click the "Settings" button and choose "Indexes"
Click "New index" button
Specify "vulners" as the "Index Name"
Choose "Vulners Dashboard for Splunk" in the "App" drop-down menu
Fill the rest of the fields accordingly

3) Installation on universal forwarder
-------------------------------------------------------------------------------
Log into the shell for your SplunkForwarder server
Install python3 prerequisites
  pip3 install distro getmac ifaddr futures
Change to the SplunkForwarder application folder:
  cd $SPLUNK_HOME/etc/apps
Extract the application from the archive file:
  tar xzf <archive location>
Verify that the app has the proper permissions for the OS:
  chown -R splunk:splunk $SPLUNK_HOME/etc/apps/vulners-lookup
Restart Splunk
  $SPLUNK_HOME/bin/splunk restart


-------------------------------------------------------------------------------
Configuration:
-------------------------------------------------------------------------------

The Vulners Dashboard for Splunk application has a simple configuration interface.
Before starting configuration of the application, you must have your Vulners API key.
You can obtain one from https://vulners.com/api-keys. You will be asked for it at the first app launch.
You can change it any time by reconfiguring application from "Manage Apps" section.

By default forwarder is set to run task to collect packages every 3000 seconds (60 minutes).
To change that create file
$SPLUNK_HOME/etc/apps/vulners-lookup/local/inputs.conf
based on
$SPLUNK_HOME/etc/apps/vulners-lookup/default/inputs.conf
