#!/bin/bash

# This is an officila packager, that runs additional checks to verify resulting app package is valid for SplunkBase.
# Install from here - https://dev.splunk.com/enterprise/docs/releaseapps/packagingtoolkit/installpkgtoolkit/

slim package -o result/ ./vulners-lookup/

# For making use of deployment units yoiu can partition the package
# Make sure to install the correct version of semantic-version package though with "pip install 'semantic_version==2.6.0'"
# Another version has a bug preventing you from splitting the package into deployment units

# slim partition -o deployment-units/ ./result/vulners-lookup-0.0.5.tar.gz
