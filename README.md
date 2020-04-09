# SSLPinning

Create instance of SSLPublicKeyPinning class and set it as delegate to NSURLSession.

SSLPublicKeyPinning *sslPublicKeyPinning = [[SSLPublicKeyPinning alloc] init];

NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration delegate:sslPublicKeyPinning delegateQueue:nil];
