//
//  AESUtil.m
//
//
//  Created by xxx on 2020/5/15.
//

#import "MMAESUtil.h"
#import <CommonCrypto/CommonCrypto.h>

const int kAESKeyLength = 32;
const int maxKeyLength = 32;
const int minKeyLength = 16;

@implementation MMAESUtil

+ (NSString *)encryptString:(NSString *)source {
    return [self encryptString:source key:nil];
}

+ (NSString *)encryptString:(NSString *)source key:(NSString *)key {
    if (key.length == 0) {
        key = [[self getUUID] stringByReplacingOccurrencesOfString:@"-" withString:@""];
    } else {
        NSAssert(key.length <= maxKeyLength, @"key too long");
        NSAssert(key.length >= minKeyLength, @"key too short");
    }

    NSMutableString *output = [NSMutableString string];
    NSString *iv = [self getIVFromKey:key];
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    NSData *sourceData = [source dataUsingEncoding:NSUTF8StringEncoding];
    NSData *resultData = [self encryptData:sourceData key:key iv:iv];
    [output appendString:[self data2HexString:keyData]];
    [output appendString:[self data2HexString:resultData]];
    return output.copy;
}

+ (NSData *)encryptData:(NSData *)data key:(NSString *)key iv:(NSString *)iv {
    char keyPtr[kCCKeySizeAES256 + 1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [data length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesDecrypted = 0;
    NSData *initVector = [iv dataUsingEncoding:NSUTF8StringEncoding];
    
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding, keyPtr, kCCKeySizeAES256, [initVector bytes], [data bytes], dataLength, buffer, bufferSize, &numBytesDecrypted);

    if(cryptStatus == kCCSuccess){
       return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    free(buffer);

    return nil;
}

+ (NSString *)decryptString:(NSString *)encryptedString {
    if (encryptedString.length <= kAESKeyLength * 2) {
        return nil;
    }
    NSString *hexKeyString = [encryptedString substringToIndex:kAESKeyLength * 2];
    NSString *keyString = [[NSString alloc] initWithData:[NSData dataWithBytes:[self hexString2Byte:hexKeyString] length:kAESKeyLength] encoding:NSUTF8StringEncoding];
    Byte *ivBytes = [self hexString2Byte:hexKeyString];
    NSString *ivString =[self getIVFromKey:[[NSString alloc] initWithData:[[NSData alloc] initWithBytes:ivBytes length:32] encoding:NSUTF8StringEncoding]];
    encryptedString = [encryptedString substringFromIndex:kAESKeyLength * 2];
    NSData *data = [[NSData alloc] initWithBytes:[self hexString2Byte:encryptedString] length:encryptedString.length / 2];
    NSData *result = [self decryptDataWithData:data andKey:keyString andIV:ivString];
    
    return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
}

+ (NSData *)decryptDataWithData:(NSData *)data andKey:(NSString *)key andIV:(NSString *)iv {
    char keyPtr[kCCKeySizeAES256 + 1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [data length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesDecrypted = 0;
    NSData *initVector = [iv dataUsingEncoding:NSUTF8StringEncoding];
    
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, keyPtr, kCCKeySizeAES256, initVector.bytes, [data bytes], dataLength, buffer, bufferSize, &numBytesDecrypted);

    if(cryptStatus == kCCSuccess){
       return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    free(buffer);

    return nil;
}

+ (NSString *)getIVFromKey:(NSString *)key {
    NSInteger ivLength = 16;
    NSMutableString *result = [NSMutableString string];
    for (int i = 0; i < ivLength; i++) {
        char c = [key characterAtIndex:i];
        if (i % 2 == 0) {
            c = (char)(c + 1);
        } else {
            c = (char)(c - 1);
        }

        [result appendFormat:@"%c", c];
    }

    return result;
}

+ (Byte *)hexString2Byte:(NSString *)hex {
    NSInteger len = hex.length / 2;
    Byte *bytes = (Byte*)malloc(len);
    for (int i = 0; i < len; i++) {
        bytes[i] = strtoul([[hex substringWithRange:NSMakeRange(i * 2, 2)] UTF8String],0,16);
    }

    return bytes;
}

+ (NSString *)data2HexString:(NSData *)data {
    if (data.length == 0) {
        return @"";
    }
    
    NSMutableString *output = [NSMutableString string];
    Byte *datas = (Byte*)[data bytes];
    for(int i = 0; i < data.length; i++){
        [output appendFormat:@"%02X", datas[i]];
    }
    
    return output.copy;
}

+ (NSString *)getUUID {
    CFUUIDRef theUUID = CFUUIDCreate(NULL);
    CFStringRef string = CFUUIDCreateString(NULL, theUUID);
    CFRelease(theUUID);
    return [(__bridge_transfer NSString *)string lowercaseString];
}

@end
