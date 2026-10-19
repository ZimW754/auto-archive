// 目录树内联编辑的逻辑测试（开发用）
// clang -fobjc-arc -framework Cocoa -framework ImageIO -o /tmp/test_tree tools/test_tree.m

#define main photo_archive_main
#include "../src/main.m"
#undef main

static void RunLoopBriefly(void) {
    [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.25]];
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        [NSApplication sharedApplication];

        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *root = @"/tmp/pa-test/tree-logic";
        [fm removeItemAtPath:root error:NULL];

        AppDelegate *d = [AppDelegate new];
        [d buildWindow];
        [d buildInterface];
        [d setSelectedSubfolders:@[ @"A", @"B" ]];
        d.rootField.stringValue = root;
        d.eventField.stringValue = @"测试";

        [d createFolders:nil];

        ArchivePlan *plan = [d currentPlan];
        NSString *eventDir = [root stringByAppendingPathComponent:[plan baseName]];
        printf("created: %s\n",
               [[[fm contentsOfDirectoryAtPath:eventDir error:NULL]
                 sortedArrayUsingSelector:@selector(localizedCompare:)]
                componentsJoinedByString:@" | "].UTF8String);

        // 1) 把 B 重命名为 C：应改磁盘 + 改标签
        NSTextField *field = [NSTextField textFieldWithString:@"C"];
        field.tag = 1001;
        [d treeFieldCommitted:field];
        RunLoopBriefly();

        printf("after rename: %s\n",
               [[[fm contentsOfDirectoryAtPath:eventDir error:NULL]
                 sortedArrayUsingSelector:@selector(localizedCompare:)]
                componentsJoinedByString:@" | "].UTF8String);
        printf("tokens: %s\n", [[[d selectedSubfolders] componentsJoinedByString:@" | "] UTF8String]);

        // 2) 新增 D：事件文件夹已存在，应立即创建
        NSTextField *newField = [NSTextField textFieldWithString:@"D"];
        newField.tag = 9999;
        d.pendingNewField = newField;
        [d treeFieldCommitted:newField];
        RunLoopBriefly();

        printf("after add: %s\n",
               [[[fm contentsOfDirectoryAtPath:eventDir error:NULL]
                 sortedArrayUsingSelector:@selector(localizedCompare:)]
                componentsJoinedByString:@" | "].UTF8String);
        printf("tokens: %s\n", [[[d selectedSubfolders] componentsJoinedByString:@" | "] UTF8String]);

        // 3) 空名称：不应改变任何东西
        NSTextField *emptyField = [NSTextField textFieldWithString:@"  "];
        emptyField.tag = 1000;
        [d treeFieldCommitted:emptyField];
        RunLoopBriefly();
        printf("after empty: tokens=%s\n", [[[d selectedSubfolders] componentsJoinedByString:@" | "] UTF8String]);

        [fm removeItemAtPath:root error:NULL];

        // 4) 照片/视频分流 + 按作者
        NSString *mediaRoot = @"/tmp/pa-test/media-logic";
        NSString *source = [mediaRoot stringByAppendingPathComponent:@"source"];
        [fm removeItemAtPath:mediaRoot error:NULL];
        [fm createDirectoryAtPath:source withIntermediateDirectories:YES attributes:nil error:NULL];
        for (NSString *name in @[ @"a.jpg", @"b.mov", @"c.jpg" ]) {
            [fm createFileAtPath:[source stringByAppendingPathComponent:name] contents:[NSData data] attributes:nil];
        }

        ArchivePlan *mediaPlan = [ArchivePlan new];
        mediaPlan.rootURL = [NSURL fileURLWithPath:mediaRoot isDirectory:YES];
        mediaPlan.date = [NSDate date];
        mediaPlan.event = @"分流测试";
        mediaPlan.subfolders = @[];
        mediaPlan.includesVideo = YES;
        mediaPlan.multiPerson = YES;
        mediaPlan.photoAuthors = @[ @"张三", @"李四" ];
        mediaPlan.sourceTag = @"拷卡";
        CreateDirectories(mediaPlan, NULL);

        NSArray *mediaFiles = @[
            [NSURL fileURLWithPath:[source stringByAppendingPathComponent:@"a.jpg"]],
            [NSURL fileURLWithPath:[source stringByAppendingPathComponent:@"b.mov"]],
            [NSURL fileURLWithPath:[source stringByAppendingPathComponent:@"c.jpg"]]
        ];
        NSDictionary *authors = @{ [source stringByAppendingPathComponent:@"a.jpg"] : @"张三" };
        ImportResult *result = [ImportResult new];
        ImportItems(mediaPlan, mediaFiles, authors, NO, NULL, result);

        NSDirectoryEnumerator *e = [fm enumeratorAtPath:mediaRoot];
        NSMutableArray *listing = [NSMutableArray array];
        for (NSString *path in e) {
            if ([path containsString:@"source"]) continue;
            [listing addObject:path];
        }
        printf("media tree:\n  %s\n",
               [[[listing sortedArrayUsingSelector:@selector(localizedCompare:)]
                 componentsJoinedByString:@"\n  "] UTF8String]);
        [fm removeItemAtPath:mediaRoot error:NULL];

        // 5) 署名优先级：手动 > 自动；多人模式下自动署名不作用于最外层
        ArchivePlan *signPlan = [ArchivePlan new];
        signPlan.rootURL = [NSURL fileURLWithPath:@"/tmp/pa-test/sign-plan" isDirectory:YES];
        signPlan.date = [NSDate date];
        signPlan.event = @"署名测试";
        signPlan.manualSignature = @"工作室";
        signPlan.autoSignature = @"张三摄影";
        signPlan.autoSignEnabled = YES;
        signPlan.multiPerson = NO;
        printf("single+manual: %s\n", [signPlan baseName].UTF8String);
        signPlan.manualSignature = @"";
        printf("single+auto:   %s\n", [signPlan baseName].UTF8String);
        signPlan.multiPerson = YES;
        printf("multi no manual: %s\n", [signPlan baseName].UTF8String);
        signPlan.manualSignature = @"工作室";
        printf("multi+manual:  %s\n", [signPlan baseName].UTF8String);

        signPlan.photoAuthors = @[ @"张三摄影", @"李四", @"未标注" ];
        NSMutableArray *authorDirs = [NSMutableArray array];
        for (NSURL *url in [signPlan leafDirectoryURLs]) {
            if ([url.path containsString:@"原始照片"] && [url.pathComponents count] > 4) {
                [authorDirs addObject:url.lastPathComponent];
            }
        }
        printf("author dirs: %s\n", [[authorDirs componentsJoinedByString:@" | "] UTF8String]);
    }
    return 0;
}
