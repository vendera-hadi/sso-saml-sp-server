# sso-saml-sp-server
This repository provides a comprehensive example of how to implement a SAML Service Provider (SP) for Single Sign-On (SSO) authentication. It demonstrates the key concepts and functionalities required to set up a SAML SP, including handling SAML responses, extracting user attributes, and integrating with Identity Providers (IdP) using Go


If you want to demonstrate with identity provider you can check this link
https://github.com/vendera-hadi/sso-saml-idp-server

## SSO Flow

![sso flow](https://user-images.githubusercontent.com/39133739/93079962-9e5d2880-f6aa-11ea-9521-feee3d4b4151.png)


## Setup idp private and public key

First please copy this line and run it into root repository or certain folder like /saml

    openssl req -newkey rsa:2048 -new -x509 -days 365 -nodes -out sp-cert.pem -keyout
    
## Setup env file

Rename **.env.example** file with **.env** and don't forget to edit the values

    BASE_URL={SP BASE URL}
    CERT_PATH=saml/sp-cert.pem
    # separate entities with '|' if multiple
    IDP_ENTITIES_IDS=http://localhost:3001/metadata|http://localhost:3002/metadata|etc
	IDP_ENTITIES_CERT=saml/idp1-cert.pem|saml/idp2-cert.pem|etc


## Run Program

Run the program using this line:

    go run main.go
