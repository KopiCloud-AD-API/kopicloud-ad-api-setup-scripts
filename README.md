# KopiCloud AD API Setup
[![KopiCloud_AD_API](https://img.shields.io/badge/kopiCloud_ad-v1.0+-blueviolet.svg)](https://www.kopicloud-ad-api.com)

Scripts to setting up the KopiCloud AD API in our environment:

- **setup-win2019.ps1** = Script to install and Configure KopiCloud AD API in Windows Server 2019/SQL Server 2019 Express 

- **setup-win2022.ps1** = Script to install and Configure KopiCloud AD API in Windows Server 2022/SQL Server 2022 Express 

## Notes

- By default, the download and installation of **SQL Server Management Studio** is disabled because it will take lots of time.

- The default Windows username is **Administrator**, and the password is **K0p1Cl0udAcc3$$**. Update the **$admin_password** variable if you want to use a different password.

## How to Set Up KopiCloud AD API

1. Get a License - Generate a free trial license (no credit card required) or purchase a license [here](https://www.kopicloud-ad-api.com/get-license).

2. Install **KopiCloud AD API** using the code in this repo.

3. Join the machine to the AD Domain to manage using the API.

4. Create a Service Account with Domain Administrators permissions for the **KopiCloud AD API**.

5. Run the **KopiCloud AD API Config tool** located in the folder **C:\KopiCloud-AD-API-Config** to finish the setup of API.

**Note:** You cannot log in to the **KopiCloud AD API Portal** using the Service Account for security reasons.

## Resources

- KopiCloud AD API Official Web Site: https://www.kopicloud-ad-api.com

- KopiCloud AD API Documentation: https://help.kopicloud-ad-api.com
