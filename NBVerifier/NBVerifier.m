//
//  NBVerifier.m
//
//  Created by Nick Brook on 16/03/2014.
//  Copyright (c) 2017 Nick Brook. All rights reserved.
//

#import "NBVerifier.h"

#if TARGET_OS_IPHONE
#include <Security/SecureTransport.h>           // just for errSSLCrypto
#include <CommonCrypto/CommonCrypto.h>
#endif

@implementation NBVerifier

+ (BOOL)verifyData:(nonnull NSData *)data publicCert:(nonnull NSData *)publicCert signature:(nonnull NSData *)signature selfSigned:(BOOL)selfSigned ignoreExpired:(BOOL)ignoreExpired {
    if(!data || !signature) return NO;
    CFDataRef certData = CFBridgingRetain(publicCert);
    SecCertificateRef publicCertificate = SecCertificateCreateWithData(CFAllocatorGetDefault(), certData);
    NSAssert(publicCertificate != NULL, @"Invalid public certificate");
    CFRelease(certData);
    
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    SecTrustRef trustRef;
    OSStatus trustResult = SecTrustCreateWithCertificates(publicCertificate, policy, &trustRef);
    NSAssert1(trustResult == errSecSuccess, @"Bad trust result: %d", (int)trustResult);
    
    if(selfSigned) {
        // self signed certificate, trust root
        NSArray *anchors = @[ (__bridge id) publicCertificate ];
        SecTrustSetAnchorCertificates(trustRef, (__bridge CFTypeRef)anchors);
    }
    
    if (@available(macOS 10.14, iOS 12.0, *)) {
        CFErrorRef errRef;
        bool res = SecTrustEvaluateWithError(trustRef, &errRef);
        if(!res && ignoreExpired && CFErrorGetCode(errRef) == errSecCertificateExpired) {
            // ignore all current exceptions
            CFDataRef cookies = SecTrustCopyExceptions(trustRef);
            SecTrustSetExceptions(trustRef, cookies);
            res = SecTrustEvaluateWithError(trustRef, &errRef);
            CFRelease(cookies);
        }
        NSAssert1(res, @"Bad trust eval result: %@", errRef);
    } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        SecTrustResultType trustEvalResult;
        trustResult = SecTrustEvaluate(trustRef, &trustEvalResult);
        NSAssert1(trustResult == errSecSuccess, @"Bad trust eval result: %d", (int)trustResult);
#pragma clang diagnostic pop
    }
    
    // trustEvalResult will not be Proceed, but this is ok, it's just because the cert is not in the keychain.  The application can just ignore this and continue using the untrusted certificate.
    SecKeyRef keyRef = SecTrustCopyPublicKey(trustRef);
    NSAssert(keyRef != NULL, @"Could not copy public key");
    CFRelease(policy);
    CFRelease(trustRef);
    CFRelease(publicCertificate);
    
    BOOL status;
    
#if TARGET_OS_IPHONE
    uint8_t     digest[CC_SHA1_DIGEST_LENGTH];
    (void) CC_SHA1([data bytes], (CC_LONG) [data length], digest);
    OSStatus err = SecKeyRawVerify(keyRef,
                                   kSecPaddingPKCS1SHA1,
                                   digest,
                                   sizeof(digest),
                                   (const uint8_t *)[signature bytes],
                                   (size_t)[signature length]
                                   );
    status = (err == errSecSuccess);
#else
    BOOL                success;
    SecTransformRef     transform;
    CFBooleanRef        result = NULL;
    CFErrorRef          errorCF;
    
    // Set up the transform.
    
    transform = SecVerifyTransformCreate(keyRef, (__bridge CFDataRef) signature, &errorCF);
    success = (transform != NULL);
    
    // Note: kSecInputIsAttributeName defaults to kSecInputIsPlainText, which is what we want.
    
    if (success) {
        success = SecTransformSetAttribute(transform, kSecDigestTypeAttribute, kSecDigestSHA1, &errorCF) != false;
    }
    
    if (success) {
        success = SecTransformSetAttribute(transform, kSecTransformInputAttributeName, (__bridge CFDataRef) data, &errorCF) != false;
    }
    
    // Run it.
    if (success) {
        result = SecTransformExecute(transform, &errorCF);
        success = (result != NULL);
    }
    
    // Process the results.
    if (success) {
        assert(CFGetTypeID(result) == CFBooleanGetTypeID());
        status = (CFBooleanGetValue(result) != false);
    } else {
        NSAssert(errorCF != NULL, @"errorCF NULL");
        status = false;
    }
    
    // Clean up.
    
    if (result != NULL) {
        CFRelease(result);
    }
    if (errorCF != NULL) {
        CFRelease(errorCF);
    }
    if (transform != NULL) {
        CFRelease(transform);
    }
#endif
    if(keyRef != NULL) {
        CFRelease(keyRef);
    }
    return status;
}

+ (nullable NSData *)base64Decode:(nonnull NSString *)base64String {
    if([NSData instancesRespondToSelector:@selector(initWithBase64EncodedString:options:)]) {
        return [[NSData alloc] initWithBase64EncodedString:base64String options:kNilOptions];
    } else {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        return [[NSData alloc] initWithBase64Encoding:base64String];
#pragma GCC diagnostic pop
    }
}

@end
