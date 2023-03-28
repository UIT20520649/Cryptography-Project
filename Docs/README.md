# Efficient and Secure File Transfer in Cloud Through Double Encryption Using AES and RSA Algorithm

## Abstract
Cloud services are already hiring information thanks to recent developments in cloud computing. Users may get low-cost storage using cloud services like Dropbox and Google Drive. Here, we give a security mechanism that offers a higher level of protection by encrypting and decrypting the files. The file that we upload to the cloud is encrypted using the double encryption approach. The two techniques are used sequentially to encrypt the file twice.
The RSA algorithm is used to encrypt the file after the AES method. The corresponding keys are being created during the execution of the algorithm. The level of security is raised by this method. Security level, speed, data secrecy, data integrity, and cipher text size are some of the different factors that we have taken into consideration here.

## Scenario
In this scenario, you are using a cloud service (Dropbox, Google Drive, Azure, etc..) to store your company's secret data. Unfortunately, the cloud service suffered a data breach that involved sensitive information of millions users after threat actors breached its AWS (Amazon Web Services) server. The data leak included customer information, internal documents for customers, customers personal documents, and other information.

<p align="center">
  <img src="https://user-images.githubusercontent.com/92283038/226251074-a5947361-be29-46ea-a3c9-7927d686b773.png" />
</p>

| Subject     | Description |
| ----------- | ----------- |
| Protected Assets | User digital assets       |
|Related-Party | Assets owner, cloud Service, assets related company|
|Security Goal | Prevent leaked user documents from being viewed|

## Solution

To solve the problem we metioned before, increase data security is necessaries. Therefore, using double encryption technique using AES and RSA algorithms to secure the data before uploading to the cloud service. The figures below will illustrate the process of uploading and downloading secure file using the mentioned method.

Here is how it work, in Figure 1 we can see the file is encrypted with AES algorithm first, then the AES key will be encrypted with RSA Public Key and then attach to the file before upload to the cloud.
<p align="center"> 
<img src="https://user-images.githubusercontent.com/92283038/227442920-38a5208d-f469-49b7-adb6-b106af609547.png">
<p align="center">Figure 1. Encryption Process</p>
</p>
First when the user register a new account, the Key Generator will generate a RSA key pair for the user as showed in Figure 2.
<p align="center"> 
<img src="https://user-images.githubusercontent.com/92283038/227447623-0ba64281-6f37-4ba4-ac0e-8027bbe80dc2.png">
<p align="center">Figure 2. KeyGen Process</p>
</p>

For decryption, user will provide the RSA Private Key, with that we can retrieve the AES Key for decrypting the file.
<p align="center"> 
<img src="https://user-images.githubusercontent.com/92283038/227451178-e4f374e3-8c88-437d-8d22-1d2dfb63194b.png">
<p align="center">Figure 3. Decryption Process</p>
</p>



## Implementation Plan

### Tools and resources
|   Tools and resources   | Description |
| ----------- | ----------- |
|Python | Programming Language|
| flask | Python Framework for Python Web Application | 
| PyCrypto| Python Library for Cryptography |
| MySQL | Data Storage | 
| Google Drive API | Interact with Google Drive Service | 


### Tasks chart

|   Name   | ID | UX/UI Design | Authentication | Cloud API | Data Encryption/Decryption | Project Management | Presentation |
| ----------- | ----------- |  :----------: | :----------: | :----------: |:----------: |:----------: |:----------: |
| Nguyễn Trần Anh Đức | 21521964 | X| | X | X| X |
| Nguyễn Hữu Tiến | 21520479 | X | | | X |  | X | 
| Lê Thanh Duẩn | 19521370 | | X | X| |  |
