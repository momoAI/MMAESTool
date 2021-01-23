//
//  AESUtil.h
//
//
//  Created by xxx on 2020/5/15.
//

#import <Foundation/Foundation.h>

/// AES加解密工具类
@interface MMAESUtil : NSObject

/// AES加密方法
/// @param source 需要加密的字符串
/// @param key AES key, 16——32字符
/// @returns 加密后的字符串
+ (NSString *)encryptString:(NSString *)source key:(NSString *)key;
+ (NSString *)encryptString:(NSString *)source; // key默认uuid

/// AES解密方法
/// @param encryptedString 加密字符串
/// @returns 解密后的字符串
+ (NSString *)decryptString:(NSString *)encryptedString;

@end
