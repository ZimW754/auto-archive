// 重命名辅助函数的安全测试（开发用）
// clang -fobjc-arc -framework Cocoa -framework ImageIO -o /tmp/test_apply tools/test_apply.m

#define main photo_archive_main
#include "../src/main.m"
#undef main

static NSURL *DirURL(NSString *base, NSString *name) {
    return [NSURL fileURLWithPath:[base stringByAppendingPathComponent:name] isDirectory:YES];
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *base = @"/tmp/pa-test/rename";
        [fm removeItemAtPath:base error:NULL];
        [fm createDirectoryAtPath:[base stringByAppendingPathComponent:@"旧名"]
      withIntermediateDirectories:YES attributes:nil error:NULL];
        [fm createDirectoryAtPath:[base stringByAppendingPathComponent:@"已存在"]
      withIntermediateDirectories:YES attributes:nil error:NULL];

        NSString *error = nil;

        // 1) 正常重命名
        BOOL ok = SafeRenameDirectory(DirURL(base, @"旧名"), DirURL(base, @"新名"), &error);
        printf("case1 ok=%d error=%s dirs=%s\n", ok, error.UTF8String ?: "-",
               [[[fm contentsOfDirectoryAtPath:base error:NULL]
                 sortedArrayUsingSelector:@selector(localizedCompare:)]
                componentsJoinedByString:@" | "].UTF8String);

        // 2) 目标已存在 → 拒绝
        error = nil;
        ok = SafeRenameDirectory(DirURL(base, @"新名"), DirURL(base, @"已存在"), &error);
        printf("case2 ok=%d error=%s\n", ok, error.UTF8String ?: "-");

        // 3) 源不存在 → 视为无需处理
        error = nil;
        ok = SafeRenameDirectory(DirURL(base, @"不存在"), DirURL(base, @"随便"), &error);
        printf("case3 ok=%d error=%s\n", ok, error.UTF8String ?: "-");

        [fm removeItemAtPath:base error:NULL];
    }
    return 0;
}
