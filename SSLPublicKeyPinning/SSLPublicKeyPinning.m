//
//  SSLPublicKeyPinning.m
//  SSL Pinning
//
//  Created by Mirza Zuhaib Beg on 03/04/20.
//  Copyright © Mirza Zuhaib Beg. All rights reserved.
//

#import "SSLPublicKeyPinning.h"
#import <CommonCrypto/CommonDigest.h>

// List of available trusted root certificates in iOS 13, iPadOS 13, macOS 10.15, watchOS 6, and tvOS 13
// https://support.apple.com/en-in/HT210770

// TODO: Replace these with actual SHA-256 Hash of Subject Public Key Information for Root CA
// SHA-256 Hash of Subject Public Key Information for Root CA 1
static NSString *kRootCA1                 = @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

// SHA-256 Hash of Subject Public Key Information for Root CA 2
static NSString *kRootCA2                 = @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

// SHA-256 Hash of Subject Public Key Information for Root CA 3
static NSString *kRootCA3                 = @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

// SHA-256 Hash of Subject Public Key Information for Root CA 4
static NSString *kRootCA4                 = @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

// SHA-256 Hash of Subject Public Key Information for Root CA 5
static NSString *kRootCA5 = @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

// These are the ASN1 headers for the Subject Public Key Info section of a certificate
// https://developer.apple.com/documentation/security/2963103-seccertificatecopykey ?
static const unsigned char rsa2048Asn1Header[] =
{
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
};

static const unsigned char rsa4096Asn1Header[] =
{
    0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00
};

static const unsigned char ecDsaSecp256r1Asn1Header[] =
{
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00
};

static const unsigned char ecDsaSecp384r1Asn1Header[] =
{
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00
};

static char *getAsn1HeaderBytes(NSString *publicKeyType, NSNumber *publicKeySize)
{
    if (([publicKeyType isEqualToString:(NSString *)kSecAttrKeyTypeRSA]) && ([publicKeySize integerValue] == 2048))
    {
        return (char *)rsa2048Asn1Header;
    }
    else if (([publicKeyType isEqualToString:(NSString *)kSecAttrKeyTypeRSA]) && ([publicKeySize integerValue] == 4096))
    {
        return (char *)rsa4096Asn1Header;
    }
    else if (([publicKeyType isEqualToString:(NSString *)kSecAttrKeyTypeECSECPrimeRandom]) && ([publicKeySize integerValue] == 256))
    {
        return (char *)ecDsaSecp256r1Asn1Header;
    }
    else if (([publicKeyType isEqualToString:(NSString *)kSecAttrKeyTypeECSECPrimeRandom]) && ([publicKeySize integerValue] == 384))
    {
        return (char *)ecDsaSecp384r1Asn1Header;
    }
    
    @throw([NSException exceptionWithName:@"Unsupported public key algorithm" reason:@"Tried to generate the SPKI hash for an unsupported key algorithm" userInfo:nil]);
}

static unsigned int getAsn1HeaderSize(NSString *publicKeyType, NSNumber *publicKeySize)
{
    if (([publicKeyType isEqualToString:(NSString *)kSecAttrKeyTypeRSA]) && ([publicKeySize integerValue] == 2048))
    {
        return sizeof(rsa2048Asn1Header);
    }
    else if (([publicKeyType isEqualToString:(NSString *)kSecAttrKeyTypeRSA]) && ([publicKeySize integerValue] == 4096))
    {
        return sizeof(rsa4096Asn1Header);
    }
    else if (([publicKeyType isEqualToString:(NSString *)kSecAttrKeyTypeECSECPrimeRandom]) && ([publicKeySize integerValue] == 256))
    {
        return sizeof(ecDsaSecp256r1Asn1Header);
    }
    else if (([publicKeyType isEqualToString:(NSString *)kSecAttrKeyTypeECSECPrimeRandom]) && ([publicKeySize integerValue] == 384))
    {
        return sizeof(ecDsaSecp384r1Asn1Header);
    }
    
    @throw([NSException exceptionWithName:@"Unsupported public key algorithm" reason:@"Tried to generate the SPKI hash for an unsupported key algorithm" userInfo:nil]);
}

@interface SSLPublicKeyPinning()

@property (nonatomic, strong) NSMutableArray *arrayCertificatePinned;

@end

@implementation SSLPublicKeyPinning

#pragma mark - NSURLSessionDelegate Methods

- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential))completionHandler {
    
    SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
    NSInteger count = (NSInteger)SecTrustGetCertificateCount(serverTrust);
    
    BOOL certificatePinned = NO;
    
    for (int index = 0; index < count; index++) {
        SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, index);
        NSString *publicKey = [self getCertificatePublicKey:certificate];
        if ([self isCertificatePinnned:publicKey]) {
            certificatePinned = YES;
            break;
        }
    }
    
    if (certificatePinned) {
       NSURLCredential *credential = [NSURLCredential credentialForTrust:serverTrust];
        [[challenge sender] useCredential:credential forAuthenticationChallenge:challenge];
        completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
    } else {
        [[challenge sender] cancelAuthenticationChallenge:challenge];
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
    }
}

#pragma mark - Private Methods

/// Method to return is Certificate Pinnned
/// @param fingerprint fingerprint
-(BOOL)isCertificatePinnned:(NSString*)publicKey {
    
    if (self.arrayCertificatePinned == nil) {
        self.arrayCertificatePinned = [[NSMutableArray alloc] init];
        [self.arrayCertificatePinned addObject:kRootCA1];
        [self.arrayCertificatePinned addObject:kRootCA2];
        [self.arrayCertificatePinned addObject:kRootCA3];
        [self.arrayCertificatePinned addObject:kRootCA4];
        [self.arrayCertificatePinned addObject:kRootCA5];
    }
    
    for (NSString *certificatePublicKey in self.arrayCertificatePinned) {
        if ([certificatePublicKey isEqualIgnoreCaseToString:publicKey]) {
            return YES;
        }
    }
    
    return NO;
}

/// Method to get Certificate Public Key
/// @param certificate certificate
-(NSString*)getCertificatePublicKey:(SecCertificateRef)certificate {
    
    SecKeyRef secKeyRefPublicKey;
    if (@available(iOS 12.0, *)) {
        secKeyRefPublicKey = SecCertificateCopyKey(certificate);
    } else {
        secKeyRefPublicKey = SecCertificateCopyPublicKey(certificate);
    }
    
    NSData *publicKeyData = (__bridge_transfer NSData *)SecKeyCopyExternalRepresentation(secKeyRefPublicKey, NULL);
    CFDictionaryRef publicKeyAttributes = SecKeyCopyAttributes(secKeyRefPublicKey);
    NSString *publicKeyType = CFDictionaryGetValue(publicKeyAttributes, kSecAttrKeyType);
    NSNumber *publicKeysize = CFDictionaryGetValue(publicKeyAttributes, kSecAttrKeySizeInBits);
    CFRelease(publicKeyAttributes);
    
    char *asn1HeaderBytes = getAsn1HeaderBytes(publicKeyType, publicKeysize);
    unsigned int asn1HeaderSize = getAsn1HeaderSize(publicKeyType, publicKeysize);
    
    CFRelease(secKeyRefPublicKey);
    
    // Generate a hash of the subject public key info
    NSMutableData *subjectPublicKeyInfoHash = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_CTX shaCtx;
    CC_SHA256_Init(&shaCtx);
    
    // Add the missing ASN1 header for public keys to re-create the subject public key info
    CC_SHA256_Update(&shaCtx, asn1HeaderBytes, asn1HeaderSize);
    
    // Add the public key
    CC_SHA256_Update(&shaCtx, [publicKeyData bytes], (unsigned int)[publicKeyData length]);
    CC_SHA256_Final((unsigned char *)[subjectPublicKeyInfoHash bytes], &shaCtx);
    
    NSString *publicKey = [self getHexString:subjectPublicKeyInfoHash];

    return publicKey;
}

/// Method to getSHA 256
/// @param data data
-(NSData *)getSHA256:(NSData*)data {
    NSMutableData *macOut = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, data.length, macOut.mutableBytes);
    return macOut;
}

/// Method to get Hex String
/// @param data data
- (NSString *)getHexString:(NSData*)data {
    const unsigned char *bytes = (const unsigned char *)data.bytes;
    NSMutableString *hex = [NSMutableString new];
    for (NSInteger i = 0; i < data.length; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
    }
    return [hex copy];
}

@end

