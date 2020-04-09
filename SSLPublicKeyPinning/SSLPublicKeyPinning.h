//
//  SSLPublicKeyPinning.h
//  SSL Pinning
//
//  Created by Mirza Zuhaib Beg on 03/04/20.
//  Copyright © Mirza Zuhaib Beg. All rights reserved.
//

#import <Foundation/Foundation.h>

/// NSString extension to provide methods for comparison
@interface NSString (Compare)

- (BOOL)isEqualIgnoreCaseToString:(NSString *)iString;

@end

@implementation NSString (Compare)

- (BOOL)isEqualIgnoreCaseToString:(NSString *)iString {
    return ([self caseInsensitiveCompare:iString] == NSOrderedSame);
}

@end

/// SSLPublicKeyPinning class will act as delegate for NSURLSession. This class will be responsible for handling NSURLAuthenticationChallenge.
@interface SSLPublicKeyPinning : NSObject <NSURLSessionDelegate>

@end
