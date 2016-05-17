//
//  NBVerifier.h
//
//  Created by Nick Brook on 13/05/2016.
//  Copyright (c) 2016 Nick Brook. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NBVerifier : NSObject

+ (BOOL)verifyData:(nonnull NSData *)data publicCert:(nonnull NSData *)publicCert signature:(nonnull NSData *)signature;

+ (nonnull NSData *)base64Decode:(nonnull NSString *)base64String;

@end
