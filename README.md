_Used API nic.ru documentation:_
https://www.nic.ru/help/upload/file/API_DNS-hosting.pdf


**DOCKER!**  
For correct execution of this class, you should use the standard letsencrypt `certbot/certbot` docker image.

HOW TO RUN DOCKER CONTAINER:

```
docker run -it --rm --name certbot \
 -v "/home/kislik/letsencrypt_nic_ru.py:/bin/letsencrypt_nic_ru.py" \
 -v "/tmp/letsencrypt.log:/tmp/letsencrypt.log" \
 -v "/etc/letsencrypt:/etc/letsencrypt" \
 -e service='SERVICENAME' \
 -e api_id='33f3uoiukjjasdfi87asldkjflajsdlf' \
 -e api_password='SDjlkjl8jlasmclasioiasoijlaJLKSJDGFHOI' \
 -e username='898443/NIC-D' \
 -e password='MyTechnoNicRuAccountPass!' \
 certbot/certbot certonly \
 -d "*.mydomain.com" \
 -d "mydomain.com" \
 --manual-public-ip-logging-ok \
 --agree-tos \
 --email mymail@gmail.com \
 --non-interactive \
 --preferred-challenges dns-01 \
 --server https://acme-v02.api.letsencrypt.org/directory \
 --manual \
 --manual-auth-hook=/bin/letsencrypt_nic_ru.py \
```


**Meaning of essential docker container arguments:**
```
-v "/home/kislik/letsencrypt_nic_ru.py:/bin/letsencrypt_nic_ru.py" ==> create docker volume with out letsencrypt_nic_ru.py
-v "/tmp/letsencrypt.log:/tmp/letsencrypt.log"                     ==> create docker volume for script logs
-v "/etc/letsencrypt:/etc/letsencrypt"                             ==> create docker volume for obtained letsencrypt certificates
-e service='SERVICENAME'                                           ==> name of nic.ru DNS-master service ( https://www.nic.ru/manager/services.cgi )
-e api_id='33f3uoiukjjasdfi87asldkjflajsdlf'                       ==> nic.ru id of registered application ( https://www.nic.ru/manager/oauth.cgi?step=oauth.app_list )
-e api_password='SDjlkjl8jlasmclasioiasoijlaJLKSJDGFHOI'           ==> nic.ru password of registered application
-e username='898443/NIC-D'                                         ==> nic.ru account login
-e password='MyTechnoNicRuAccountPass!'                            ==> nic.ru account password
-d "*.mydomain.com"                                                ==> desired wildcard domain name
-d "mydomain.com"                                                  ==> desired single domain name
--manual-auth-hook=/bin/letsencrypt_nic_ru.py                      ==> path to letsencrypt_nic_ru.py script
```

_In the example above the module's logs will be written in path '/tmp/letsencrypt.log'_

