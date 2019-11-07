# IBM UrbanCode Deploy - Venafi Plug-in
---
Note: This is not the plugin distributable! This is the source code. To find the installable plugin, go into the 'Releases' tab, and download a stable version.

### License
This plugin is protected under the [Eclipse Public 1.0 License](http://www.eclipse.org/legal/epl-v10.html)

### Documentation
See the associated pdf file for detailed information on how to use the plugin steps and how to assemble the steps into useful UrbanCode processes.

### Compatibility
	The IBM UrbanCode Deploy automation plugin uses Venafi's REST API.
	This plug-in requires version 6.1.1 or later of IBM UrbanCode Deploy.

### Installation
	The packaged zip is located in the releases folder. No special steps are required for installation. See Installing plug-ins in UrbanCode Deploy. Download this zip file if you wish to skip the manual build step. Otherwise, download the entire Venafi-UCD project and run the `gradle` command in the top level folder. This should compile the code and create 	a new distributable zip within the `build/distributions` folder. Use this command if you wish to make your own changes to the plugin.

### History
    Version 19
        - Community GitHub Release

    Version 20
	New steps added for :

	Generate certificate CSR – Create a certificate signing request that may then be submitted to Venafi.
	Get Venafi Policy – Retreive the details of the Venafi policy associated with a specific policy folder.
	Submit CSR to Venafi – Submit the previously created CSR to Venafi for processing.
	Submit custom fields to Venafi – Suppliment a previously submitted certificate request with custom field values.
    Version 28
        - Fixed error where different versions of Venafi return incompatible certificate data.
    Version 29
        - Fixed plugin upgrade process from older versions.

### How to build the plugin from command line:

1. Navigate to the base folder of the project through command line.
2. Make sure that there is a build.gradle file in the root directory and execute the 'gradle' command.
3. The built plugin is located at `build/distributions/Venafi-UCD-vdev.zip`
