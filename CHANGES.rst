v0.7.0, 10-8-2016
    * Added Access Control, Template, Rule, SSO, FQDN, Site, Cluster, Range, CustomLocation, Certificate and Interface objects. Added more Virtual Service parameters.
v0.6.19, 23-6-2016
    * Added RS parameters for VirtualService
v0.6.0, 12-5-2016
    * Added some user management
v0.5.11, 28-3-2016
    * Added capabilities property to LoadMaster class
v0.5.0, 22-3-2016
    * Added subvs management support
v0.4.18, 19-2-2016
    * Added ExtraPorts and QoS parameters
v0.4.17, 10-2-2016
    * SubVSs are supported by the VirtualService class
v0.4.10, 26-1-2016
    * When only a single RS is present, get_real_servers will behave correctly
v0.4.9, 26-1-2016
    * AltAddress field was added to the virtual service read
v0.4.4, 18-1-2016
    * Autopopulate RS fields after save
v0.4.3, 18-1-2016
    * Autopopulate VS fields after save
v0.4.2, 18-1-2016
    * Return responses from deletes
v0.4.1, 18-1-2016
    * Get real servers from a virtual service function added (get_real_servers)
v0.4.0, 15-1-2016
    * Added basic VS and RS manipulation
v0.3.24, 18-11-2015
    * add kill_asl_instance command
v0.3.23, 16-11-2015
    * pass useless expections instead of log clogging
v0.3.22, 16-11-2015
    * fix returns
v0.3.21, 16-11-2015
    * Lots of tests
v0.3.20, 02-11-2015
    * Add alsi_license method
v0.3.19, 27-10-2015
    * Restore command can have parameters
v0.3.18, 23-10-2015
    * Backup folder
v0.3.17, 23-10-2015
    * Backup function creates a file
v0.3.16, 23-10-2015
    * Backup function creates a file
v0.3.15, 23-10-2015
    * Backup/Restore functions
v0.3.14, 20-10-2015
    * add get_sdn_info function
v0.3.13, 15-10-2015
    * Log errors instead of exceptions to stop traceback spam
v0.3.12, 13-10-2015
    * Manage templates command added
v0.3.11, 12-10-2015
    * Add port to enable_api command
v0.3.10, 08-10-2015
    * Remove timeouts for posts
v0.3.9, 08-10-2015
    * Better timeouts
v0.3.8, 08-10-2015
    * Added the ability to set the port
v0.3.7, 07-10-2015
    * Added ConnectionTimeoutException
v0.3.6, 07-10-2015
    * Added InvalidOperationException
v0.3.5, 06-10-2015
    * Fix enable API 2
v0.3.4, 06-10-2015
    * Fix enable API 2
v0.3.3, 06-10-2015
    * Fix enable API
v0.3.2, 29-09-2015
    * Get / set updated urls
v0.3.1, 22-09-2015
    * updated get_sdn_controller
    * command not found error handled with addons
v0.3.0, 22-09-2015
    * Add get_sdn_controller
    * More granular exceptions
v0.2.9, 03-09-2015
    * Add stats function for loadmasters
v0.2.8, 17-07-2015
    * Add reboot function
    * Add firmware update function
v0.2.7, 17-07-2015
    * Can now enable LoadMaster APIs
    * Context manager support
v0.2.5, 10-07-2015
    * Added upload_firmware function to LoadMaster
v0.2.2, 02-07-2015
    * Fix installer issues
v0.2.0, 02-07-2015
    * Redesign of of base functionality
v0.1.2, 08-04-2015
    * Renamed package to python_kemptech_api
v0.1.1, 08-04-2015
    * Added python 2.7 to setup.py
v0.1.0, 08-04-2015 -- Initial release.
