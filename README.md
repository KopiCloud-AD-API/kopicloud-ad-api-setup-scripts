# KopiCloud AD API Setup
[![KopiCloud_AD_API](https://img.shields.io/badge/kopiCloud_ad-v1.0+-blueviolet.svg)](https://www.kopicloud-ad-api.com)

Scripts to setting up the KopiCloud AD API in our environment:

- **setup-win2019.ps1** = Script to install and Configure KopiCloud AD API in Windows Server 2019/SQL Server 2019 Express 

- **setup-win2022.ps1** = Script to install and Configure KopiCloud AD API in Windows Server 2022/SQL Server 2022 Express 

## Notes

- By default, the download and install of **SQL Server Management Studio** is disabled because it will take lots of time.

- The default Windows username is **Administrator**, and the password is **K0p1Cl0ud**. Update the **$admin_password** variable if you want to use a different password.

## How to Set Up KopiCloud AD API

1. Get a License - Generate a free trial license (no credit card required) or purchase a license [here](https://www.kopicloud-ad-api.com/get-license)

2. Install **KopiCloud AD API** using one of the scripts listed above

3. Join the machine to the AD Domain to manage to the API

4. Run the **KopiCloud AD API Config tool** located in the folder **C:\KopiCloud-AD-API-Config**
