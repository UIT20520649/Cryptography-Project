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
| Protected Assets | User's digital assets       |
|Related-Party | Assets's owner, cloud Service, assets's related company|
|Security Goal | Prevent leaked user's documents from being viewed|

## Solution

To solve the problem we metioned before, increase data security is necessaries. Therefore, using double encryption technique using AES and RSA algorithms to secure the data before uploading to the cloud service. The figures below will illustrate the process of uploading and downloading secure file using the mentioned method.

<p align="center">
  <img src="https://user-images.githubusercontent.com/92283038/226259242-a8667334-87dd-4cc0-a289-30cafa94037d.png" />
</p>

<p align="center">
Figure 1. Uploading File Process
</p>

<p align="center">
  <img src="https://user-images.githubusercontent.com/92283038/226261577-c98380e3-52ab-479c-9b51-2b5089a8969d.png" />
</p>

<p align="center">
Figure 2. Downloading File Process
</p>

## Deploy Plan

### Tools and resources
|   Tools and resources   | Description |
| ----------- | ----------- |
|Python | Programming Language|
| flask | Python Library for Python Web Application | 
| PyCrypto| Python Library for Cryptography |
| MySQL | Data Storage | 
| Google Drive API | Interact with Google Drive Service | 


### Duty chart

|   Name   | ID | Duty | 
| ----------- | ----------- | ----------- |
| Nguyễn Trần Anh Đức | 21521964 | |
| Nguyễn Hữu Tiến | 21520479 | |
| Lê Thanh Duẩn | 19521370 | |
