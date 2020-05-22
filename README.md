# Splunk - Vulners App

Vulners Application for Splunk allows you to collect information about your system packages and their vulnerabilities
![](./docs/dashboard.png)

```
index=vulners | lookup vulnerslook os version package | stats list(cve) as cve values(fix) as fix by package 
```

## Installation

### Notes
- Current [Distro](./result/vulners-lookup-0.0.1.tar.gz) was created on a single machine environment. It was tested in a simple installation whith one indexer and search head on a single machine as well. As a result it is a whole package that includes parts for all three Splunk components: forwarder, indexer and search head. 
- In spite of Splunk official documentation for [AppInspect](https://dev.splunk.com/enterprise/docs/releaseapps/appinspect/appinspectreferencetopics/splunkappinspectcheck/#Indexesconf-file-standards) claiming no indexes definitions are allowed, this package still has [one](./vulners-lookup/default/indexes.conf) for easier use in a single machine installation. Note that you will have to delete the file and create a new index with the same name on your indexer if you have a separate one (step 4 in the installation process below).
- The following installation process is a straightforward one for a case without indexers and uses the provided package as is. The package has however been tested against generating deployment units, look at [generate DU](#using-slim) for a quick reference.

#### 1. Install Dashboard App

 - In Splunk dashboard on your search-head go to 
    
    Apps -> Install app from file -> choose [vulners-lookup-*.tar.gz](./result/vulners-lookup-0.0.1.tar.gz)

 - Set data receiver, go to 
    Settings -> Forwarding and receiving -> Configure receiving -> New Receiving port

![](./docs/receiver.jpeg)

- [restart](https://docs.splunk.com/Documentation/Splunk/8.0.3/Admin/StartSplunk) Splunk Enterprise


#### 2. Install Forwarder App


 - Install following Python libs on forwarder machines 
    ```bash 
    pip3 install distro getmac ifaddr futures
    ```

 - unpack vulners_lookup.tar.gz into **$SPLUNK_FORWARDER_HOME/etc/apps/**

 - [restart](https://docs.splunk.com/Documentation/Forwarder/8.0.3/Forwarder/Starttheuniversalforwarder) Splunk Forwarder

#### 3. Add Vulners-API key

 - get API key at https://vulners.com/
  ![](./docs/vulners.png)
  
 - add key in Splunk Vulners Dashboard 
 ![](./docs/api.png)
 
#### 4. Create vulners index
Since the forwarder app forwards data to the index named **vulners**, it has to be present in the system. 

## Using [slim](https://dev.splunk.com/enterprise/docs/releaseapps/packagingtoolkit/installpkgtoolkit)
**NB** The process of DU creation has been tested and should work without issues. However no tests have been conducted regarding use of deployment server. Any feedback on that would be appreciated.

 - Install slim as in the instruction (take note of [this bug](https://answers.splunk.com/answers/773820/error-while-running-slim-partition-command.html) though)
 - Create a package
 ```
slim package -o result/ ./vulners-lookup/
```
 - Partition the package into deployment units
 ```
 slim partition -o deployment-units/ vulners-lookup-0.0.1.tar.gz
 ```
 - Use your deployment server for installation
 
 
 
