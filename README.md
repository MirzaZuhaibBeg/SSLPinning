# SSLPinning

Create instance of SSLPublicKeyPinning class and set it as delegate to NSURLSession.

SSLPublicKeyPinning *sslPublicKeyPinning = [[SSLPublicKeyPinning alloc] init];

NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration delegate:sslPublicKeyPinning delegateQueue:nil];

SSL:
SSL stands for Secure Socket Layer, which is a protocol for creating an encrypted connection between client and server. It ensures that all data pass in network will be private and integral.

SSL Certificate:
SSL Certificates are small data files that digitally bind a cryptographic key to an organization’s details. When installed on a web server, it activates the padlock and the https protocol and allows secure connections from a web server to a browser. Typically, SSL is used to secure credit card transactions, data transfer and logins, and more recently is becoming the norm when securing browsing of social media sites.

SSL Pinning:
SSL pinning is the solution to prevent Man-In-The-Middle (MITM) attack. SSL pinning will ensure that client connect with designated server. The public key of server certificate will be saved in app bundle. Then, when client receives certificate from server, it then compares 2 certificates public key to make sure that they are the same before establishing the connection.
