# -*- coding: UTF-8 -*- 

from python_kemptech_api import LoadMaster as loadmaster 
LoadMaster_IP = " " # Your LoadMaster’s administrative IP 
# Note: To improve security, avoid using plaintext login and passwords and consider using environmental variables instead.  
LoadMaster_User = " " # Your LoadMaster’s Login User 
LoadMaster_Password = " " # Your LoadMaster’s User’s Password 
LoadMaster_Port = "443" # By default this is 443.  
lm = loadmaster(LoadMaster_IP, LoadMaster_User, LoadMaster_Password, LoadMaster_Port)  
virtual_services = lm.get_virtual_services() 
for each_virtual_service in virtual_services: 
    print(each_virtual_service) 
