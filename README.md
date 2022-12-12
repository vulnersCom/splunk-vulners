# Vulners App for Splunk

Vulners Application for Splunk allows one to use Splunk as a Vulnerability assessment platform and security scanner.



![](./docs/dashboard.png)

### Notes
- The app was tested in a simple installation as well as in a clustered (search head cluster) installation
- As a result it is a whole package that includes parts for three Splunk components: forwarders, indexers (indexer cluster) and search heads (search head clusters). 


## Installation

Installation process is described in details within the [app directory](./vulners-lookup/README.md)

___

## Usage

#### 1. Search for packages collected using python scripted input from the app
By default scripted input is sending information about packages hourly. You must enable it before it starts to collect the data.
To see collected packages run search
```
index=vulners
```

#### 2. Ad-hoc Vulners audit request
Vulners application is running audit script automatically at 9 o'clock in the morning. You must enable it before it starts to work.
Alternatively you can hit saved search
```
| savedsearch vulners_report 
```


## Using [slim](https://dev.splunk.com/enterprise/docs/releaseapps/packagingtoolkit/installpkgtoolkit)

 - Install slim as in the instruction (take note of [this bug](https://answers.splunk.com/answers/773820/error-while-running-slim-partition-command.html) though)
 - Create a package
 ```
slim package -o result/ ./vulners-lookup/
```
 
 
 
