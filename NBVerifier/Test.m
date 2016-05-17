//
//  iOSTest.m
//  iOSTest
//
//  Created by Nick Brook on 13/05/2016.
//
//

#import <XCTest/XCTest.h>
#import "NBVerifier.h"

#define getTestFilePath(file) [[[NSBundle bundleForClass:[self class]] resourcePath] stringByAppendingPathComponent:file]

NSString * publicCert = @"MIIDXjCCAsegAwIBAgIJANwHAsSs1xG2MA0GCSqGSIb3DQEBBQUAMH0xCzAJBgNVBAYTAkdCMQ8wDQYDVQQIEwZMb25kb24xDzANBgNVBAcTBkxvbmRvbjETMBEGA1UEChMKTmljayBCcm9vazEVMBMGA1UEAxMMbmlja2Jyb29rLm1lMSAwHgYJKoZIhvcNAQkBFhFucmJyb29rQGdtYWlsLmNvbTAgFw0xNjA1MTMxNjMzNDNaGA80NzU0MDQwOTE2MzM0M1owfTELMAkGA1UEBhMCR0IxDzANBgNVBAgTBkxvbmRvbjEPMA0GA1UEBxMGTG9uZG9uMRMwEQYDVQQKEwpOaWNrIEJyb29rMRUwEwYDVQQDEwxuaWNrYnJvb2subWUxIDAeBgkqhkiG9w0BCQEWEW5yYnJvb2tAZ21haWwuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJCBXBRhO3x8USYIKZgEQrXzuGA+8jyQZQOMZ2tWHmrmj4e4ec1vMWGvxusS39ChtnAephzFLXxa8M3R/4cJ0mfUHs5cmJtzeyjDzyN22G8jrfseCwfS0sl16EgEDgx9H9Fm9/lN3HltnIo1uWikE53SlVLissEta3CdQNFAWXmQIDAQABo4HjMIHgMB0GA1UdDgQWBBSR6UWvEE6JOK6+louSmzFXaaZe0jCBsAYDVR0jBIGoMIGlgBSR6UWvEE6JOK6+louSmzFXaaZe0qGBgaR/MH0xCzAJBgNVBAYTAkdCMQ8wDQYDVQQIEwZMb25kb24xDzANBgNVBAcTBkxvbmRvbjETMBEGA1UEChMKTmljayBCcm9vazEVMBMGA1UEAxMMbmlja2Jyb29rLm1lMSAwHgYJKoZIhvcNAQkBFhFucmJyb29rQGdtYWlsLmNvbYIJANwHAsSs1xG2MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADgYEAWLxqdLsDCf/9J/cUNzfCl+JZhw9/R5TVtBAq8TRdJ+K7Tc3XrlTdtD1xfxTjN0dYWjBULqDWahM9DToPWcEki678V+KgRV3hPa5UnBonlHPOFU12SBOV/W7LYi38lU6W6cEpDaKAFduRECDn6jxms7Tklv21x9suLSqS9PmAyow=";

@interface Test : XCTestCase

@end

@implementation Test

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testVerify
{
    NSData *testBlob = [NSData dataWithContentsOfFile:getTestFilePath(@"test.blob")];
    NSData *certData = [NBVerifier base64Decode:publicCert];
    
    // correct signature
    NSData *sig = [NBVerifier base64Decode:@"bpUApzX+QH9yn5r7lV2qkorjlJ26b/ZfP8RSHJy2Rqs/WqelnIfNrxE3ireLmDmginDMbnznRrX+6fJAMgCACrbt7TldzeCE809VFQVdpXE821QIrEFdZjIjXj6F3oXE03WOujDj699fp8oeA7X0EaULAjeoBv2VO0ZB5Uc1gaM="];
    XCTAssertNotNil(sig);
    XCTAssertTrue([NBVerifier verifyData:testBlob publicCert:certData signature:(NSData * _Nonnull)sig]);
    
    // incorrect signature
    sig = [NBVerifier base64Decode:@"merESPJK5MspZY3NRMQMRwnJaDxx0Txk6Io+KDA3Bw1wz5i+LrS1ybAQAHT/RWWa6XUsWIcIeqxNJZvykoiWKly6WRr8dVmlWMLYZJLxzXEuLsUR3FgPYp9im+ei5YR3hZi8rtqYjrzthlbQxHH9mpgaVfuDYjR2szZIGrIa/04="];
    XCTAssertNotNil(sig);
    XCTAssertFalse([NBVerifier verifyData:testBlob publicCert:certData signature:(NSData * _Nonnull)sig]);
}

@end
