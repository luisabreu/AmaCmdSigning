# AmaCmdSigning
Demo project for showing how to use the AMA CMD Documento Digital Signing. 

## What's in it
The solution was entirely written in .NET 5.0 (C#) and it consists of 2 projects: 
* an assembly which illustrates the required code for interacting with AMA and the itext7 (used for signing the document)
* a console app which shows how to consume the assembly classes

### How to use it
In order to use the project, you'll need to pass the AMA credentials and URL for calling the signing web service. The demo project loads these settings from an existing JSON file that should look like this:

```JSON
{"username": "your_ama_username", "password": "your_ama_password", "applicationId": "your_registered_ama_app_id", "webServiceUrl": "ama_web_Service_url"}
```

You'll also need to set the path to the AMA's cert file that will be used for encyrpting/decrypting data sent to AMA (change the code for the <code>LoadAmaCertificate</code> method on the console).

The demo code uses freetsa for timestamping and uses clr and ocsp for revocation status. These items are optional and if you're using self-signed certificates, you'll have to add

### About the code
This is demo code. You can use it as you wish, but please notice that it should be hardened if you intend to use it on a real app. 

