# -*- coding: UTF-8 -*- 
from python_kemptech_api import LoadMaster as loadmaster 

loadmaster_ip = " " # Your LoadMaster administrative IP 
# Note: To improve security, avoid using plaintext login and passwords and consider using environmental variables instead.  
loadmaster_login = " " # Your LoadMaster user login
loadmaster_password = " " # Your LoadMaster user password 
loadmaster_port = "443" # By default this is 443.  
lm = loadmaster(loadmaster_ip, loadmaster_login, loadmaster_password, loadmaster_port)  

virtual_services = lm.get_virtual_services()

for virtual_service in virtual_services:
    real_services = virtual_service.get_real_servers()
    for real_service in real_services:
        print(real_service)

