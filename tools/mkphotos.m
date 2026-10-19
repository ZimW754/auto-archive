// 测试素材生成器：生成带 EXIF 的 JPEG、无 EXIF 的 PNG、视频/音频占位、预览文件等。
// 仅开发测试使用：
//   clang -fobjc-arc -framework Cocoa -framework ImageIO -o /tmp/mkphotos tools/mkphotos.m
//   /tmp/mkphotos <输出目录> [作者]         普通测试照片
//   /tmp/mkphotos --fixtures <输出目录>     按功能分类的整套测试素材

#import <Cocoa/Cocoa.h>
#import <ImageIO/ImageIO.h>

static void WriteJPEG(NSString *path, NSString *dateString, int index, NSString *artist,
                      NSString *make, NSString *model, NSString *serial,
                      NSString *lens, BOOL includeMetadata) {
    size_t w = 900, h = 600;
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(NULL, w, h, 8, 0, cs, kCGImageAlphaPremultipliedLast);
    CGColorSpaceRelease(cs);

    NSGraphicsContext *gc = [NSGraphicsContext graphicsContextWithCGContext:ctx flipped:NO];
    [NSGraphicsContext saveGraphicsState];
    [NSGraphicsContext setCurrentContext:gc];

    NSColor *a = [NSColor colorWithCalibratedHue:(index % 10) / 10.0 saturation:0.55 brightness:0.90 alpha:1.0];
    NSColor *b = [NSColor colorWithCalibratedHue:(index % 10) / 10.0 saturation:0.75 brightness:0.55 alpha:1.0];
    NSGradient *g = [[NSGradient alloc] initWithStartingColor:a endingColor:b];
    [g drawInRect:NSMakeRect(0, 0, w, h) angle:45];

    NSString *text = [NSString stringWithFormat:@"IMG_%04d\n%@", index, dateString ?: @"NO EXIF"];
    NSDictionary *attrs = @{
        NSFontAttributeName : [NSFont systemFontOfSize:48 weight:NSFontWeightSemibold],
        NSForegroundColorAttributeName : [NSColor colorWithWhite:1.0 alpha:0.85]
    };
    [text drawAtPoint:NSMakePoint(48, 340) withAttributes:attrs];

    [NSGraphicsContext restoreGraphicsState];
    CGImageRef image = CGBitmapContextCreateImage(ctx);
    CGContextRelease(ctx);

    NSURL *url = [NSURL fileURLWithPath:path];
    CGImageDestinationRef dest = CGImageDestinationCreateWithURL((__bridge CFURLRef)url,
                                                                CFSTR("public.jpeg"), 1, NULL);
    NSMutableDictionary *props = [NSMutableDictionary dictionary];
    props[(__bridge NSString *)kCGImageDestinationLossyCompressionQuality] = @0.8;

    if (includeMetadata) {
        NSMutableDictionary *exif = [@{
            (__bridge NSString *)kCGImagePropertyExifDateTimeOriginal : dateString ?: @"",
            (__bridge NSString *)kCGImagePropertyExifDateTimeDigitized : dateString ?: @""
        } mutableCopy];
        if (serial.length) exif[(__bridge NSString *)kCGImagePropertyExifBodySerialNumber] = serial;
        if (lens.length) exif[(__bridge NSString *)kCGImagePropertyExifLensModel] = lens;

        NSMutableDictionary *tiff = [@{
            (__bridge NSString *)kCGImagePropertyTIFFMake : make ?: @"SONY",
            (__bridge NSString *)kCGImagePropertyTIFFModel : model ?: @"ILCE-7M4"
        } mutableCopy];
        if (artist.length && ![artist isEqualToString:@"-"]) {
            tiff[(__bridge NSString *)kCGImagePropertyTIFFArtist] = artist;
        }
        props[(__bridge NSString *)kCGImagePropertyExifDictionary] = exif;
        props[(__bridge NSString *)kCGImagePropertyTIFFDictionary] = tiff;
    }

    CGImageDestinationAddImage(dest, image, (__bridge CFDictionaryRef)props);
    CGImageDestinationFinalize(dest);
    CFRelease(dest);
    CGImageRelease(image);
}

static void WritePNG(NSString *path) {
    size_t w = 400, h = 300;
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(NULL, w, h, 8, 0, cs, kCGImageAlphaPremultipliedLast);
    CGColorSpaceRelease(cs);
    CGContextSetRGBFillColor(ctx, 0.85, 0.9, 0.95, 1.0);
    CGContextFillRect(ctx, CGRectMake(0, 0, w, h));
    CGImageRef image = CGBitmapContextCreateImage(ctx);
    CGContextRelease(ctx);

    NSURL *url = [NSURL fileURLWithPath:path];
    CGImageDestinationRef dest = CGImageDestinationCreateWithURL((__bridge CFURLRef)url,
                                                                CFSTR("public.png"), 1, NULL);
    CGImageDestinationAddImage(dest, image, NULL);
    CGImageDestinationFinalize(dest);
    CFRelease(dest);
    CGImageRelease(image);
}

static NSString *gFixtureBase;

static NSString *FixturePath(NSString *folder, NSString *name) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *dir = [gFixtureBase stringByAppendingPathComponent:folder];
    [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:NULL];
    return [dir stringByAppendingPathComponent:name];
}

static void FixtureJPEG(NSString *folder, NSString *name, int index, NSString *date,
                        NSString *artist, NSString *make, NSString *model,
                        NSString *serial, NSString *lens) {
    WriteJPEG(FixturePath(folder, name), date, index, artist, make, model, serial, lens, YES);
}

static void FixtureJPEGNoMeta(NSString *folder, NSString *name, int index) {
    WriteJPEG(FixturePath(folder, name), nil, index, @"-", nil, nil, nil, nil, NO);
}

static void FixturePNG(NSString *folder, NSString *name) {
    WritePNG(FixturePath(folder, name));
}

static void FixtureEmpty(NSString *folder, NSString *name) {
    [[NSData data] writeToFile:FixturePath(folder, name) atomically:YES];
}

static void FixtureText(NSString *folder, NSString *name, NSString *text) {
    [text writeToFile:FixturePath(folder, name) atomically:YES
             encoding:NSUTF8StringEncoding error:NULL];
}

static void FixtureCopy(NSString *srcFolder, NSString *srcName,
                        NSString *dstFolder, NSString *dstName) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *src = FixturePath(srcFolder, srcName);
    NSString *dst = FixturePath(dstFolder, dstName);
    [fm removeItemAtPath:dst error:NULL];
    [fm copyItemAtPath:src toPath:dst error:NULL];
}

static void MakeFixtures(NSString *base) {
    gFixtureBase = base;
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm createDirectoryAtPath:base withIntermediateDirectories:YES attributes:nil error:NULL];

    // 01 单人基础：同一作者、跨两天，最早日期 2026-05-19
    FixtureJPEG(@"01-单人基础", @"IMG_1001.jpg", 1001, @"2026:05:20 09:00:00",
                @"林川", @"SONY", @"ILCE-7M4", @"SN-A1", @"FE 24-70mm F2.8 GM II");
    FixtureJPEG(@"01-单人基础", @"IMG_1002.jpg", 1002, @"2026:05:20 10:30:00",
                @"林川", @"SONY", @"ILCE-7M4", @"SN-A1", @"FE 24-70mm F2.8 GM II");
    FixtureJPEG(@"01-单人基础", @"IMG_1003.jpg", 1003, @"2026:05:20 14:15:00",
                @"林川", @"SONY", @"ILCE-7M4", @"SN-A1", @"FE 24-70mm F2.8 GM II");
    FixtureJPEG(@"01-单人基础", @"IMG_1004.jpg", 1004, @"2026:05:20 18:40:00",
                @"林川", @"SONY", @"ILCE-7M4", @"SN-A1", @"FE 24-70mm F2.8 GM II");
    FixtureJPEG(@"01-单人基础", @"IMG_1005.jpg", 1005, @"2026:05:19 21:05:00",
                @"林川", @"SONY", @"ILCE-7M4", @"SN-A1", @"FE 24-70mm F2.8 GM II");

    // 02 多人双机位：林川 SONY + 阿哲 Canon
    FixtureJPEG(@"02-多人-双机位", @"A_2001.jpg", 2001, @"2026:05:20 09:10:00",
                @"林川", @"SONY", @"ILCE-7M4", @"SN-A1", @"FE 24-70mm F2.8 GM II");
    FixtureJPEG(@"02-多人-双机位", @"A_2002.jpg", 2002, @"2026:05:20 09:12:00",
                @"林川", @"SONY", @"ILCE-7M4", @"SN-A1", @"FE 24-70mm F2.8 GM II");
    FixtureJPEG(@"02-多人-双机位", @"A_2003.jpg", 2003, @"2026:05:20 09:15:00",
                @"林川", @"SONY", @"ILCE-7M4", @"SN-A1", @"FE 24-70mm F2.8 GM II");
    FixtureJPEG(@"02-多人-双机位", @"B_2101.jpg", 2101, @"2026:05:20 09:11:00",
                @"阿哲", @"Canon", @"EOS R5", @"SN-B2", @"RF 24-70mm F2.8 L IS USM");
    FixtureJPEG(@"02-多人-双机位", @"B_2102.jpg", 2102, @"2026:05:20 09:13:00",
                @"阿哲", @"Canon", @"EOS R5", @"SN-B2", @"RF 24-70mm F2.8 L IS USM");
    FixtureJPEG(@"02-多人-双机位", @"B_2103.jpg", 2103, @"2026:05:20 09:16:00",
                @"阿哲", @"Canon", @"EOS R5", @"SN-B2", @"RF 24-70mm F2.8 L IS USM");

    // 03 无作者、有序列号：用于未知身份弹窗
    FixtureJPEG(@"03-无作者-有序列号", @"CAM_3001.jpg", 3001, @"2026:05:20 11:00:00",
                @"-", @"SONY", @"ILCE-7M4", @"SN-C3", @"FE 35mm F1.4 GM");
    FixtureJPEG(@"03-无作者-有序列号", @"CAM_3002.jpg", 3002, @"2026:05:20 11:05:00",
                @"-", @"SONY", @"ILCE-7M4", @"SN-C3", @"FE 35mm F1.4 GM");
    FixtureJPEG(@"03-无作者-有序列号", @"CAM_3003.jpg", 3003, @"2026:05:20 11:10:00",
                @"-", @"SONY", @"ILCE-7M4", @"SN-C3", @"FE 35mm F1.4 GM");

    // 04 完全无元数据
    FixturePNG(@"04-无元数据", @"export-1.png");
    FixtureJPEGNoMeta(@"04-无元数据", @"export-2.jpg", 4002);

    // 05 视频与音频
    FixtureEmpty(@"05-视频与音频", @"CLIP_4001.MOV");
    FixtureEmpty(@"05-视频与音频", @"CLIP_4002.MP4");
    FixtureEmpty(@"05-视频与音频", @"TRACK_4001.mp3");
    FixtureEmpty(@"05-视频与音频", @"TRACK_4002.wav");

    // 06 大疆预览
    FixtureEmpty(@"06-大疆预览", @"DJI_5001.MP4");
    FixtureText(@"06-大疆预览", @"DJI_5001.LRF", @"DJI LRF low-resolution preview placeholder\n");
    FixtureJPEG(@"06-大疆预览", @"DJI_5001.JPG", 5001, @"2026:05:20 12:00:00",
                @"林川", @"DJI", @"FC8282", @"SN-D4", @"DJI DL 24mm F2.8");

    // 07 日期不一致
    FixtureJPEG(@"07-日期不一致", @"DAY_6001.jpg", 6001, @"2026:05:18 08:00:00",
                @"林川", @"SONY", @"ILCE-7M4", @"SN-A1", @"FE 24-70mm F2.8 GM II");
    FixtureJPEG(@"07-日期不一致", @"DAY_6002.jpg", 6002, @"2026:05:22 19:00:00",
                @"林川", @"SONY", @"ILCE-7M4", @"SN-A1", @"FE 24-70mm F2.8 GM II");

    // 08 重复与重名
    FixtureJPEG(@"08-重复与重名", @"DUP_7001.jpg", 7001, @"2026:05:20 10:00:00",
                @"林川", @"SONY", @"ILCE-7M4", @"SN-A1", @"FE 24-70mm F2.8 GM II");
    FixtureJPEG(@"08-重复与重名", @"DUP_7002.jpg", 7002, @"2026:05:20 10:05:00",
                @"林川", @"SONY", @"ILCE-7M4", @"SN-A1", @"FE 24-70mm F2.8 GM II");
    FixtureCopy(@"08-重复与重名", @"DUP_7001.jpg", @"08-重复与重名/A", @"DUP_7001.jpg");
    FixtureJPEG(@"08-重复与重名/B", @"DUP_7002.jpg", 7010, @"2026:05:20 10:10:00",
                @"林川", @"SONY", @"ILCE-7M4", @"SN-A1", @"FE 24-70mm F2.8 GM II");
    FixtureCopy(@"08-重复与重名", @"DUP_7001.jpg", @"08-重复与重名/C", @"DUP_7001-copy.jpg");

    // 09 特殊名称与自定义扩展
    FixtureJPEG(@"09-特殊名称", @"毕业 典礼（合影）1.jpg", 9001, @"2026:05:20 13:00:00",
                @"林川", @"SONY", @"ILCE-7M4", @"SN-A1", @"FE 24-70mm F2.8 GM II");
    FixtureJPEG(@"09-特殊名称", @"带 空格 的文件 3.jpg", 9003, @"2026:05:20 13:10:00",
                @"林川", @"SONY", @"ILCE-7M4", @"SN-A1", @"FE 24-70mm F2.8 GM II");
    FixtureCopy(@"09-特殊名称", @"毕业 典礼（合影）1.jpg", @"09-特殊名称", @"UPPER.JPG");
    FixtureCopy(@"09-特殊名称", @"带 空格 的文件 3.jpg", @"09-特殊名称", @"custom.xyz");

    // 10 混合格式
    FixtureJPEG(@"10-混合格式", @"MIX_8001.jpg", 8001, @"2026:05:20 08:00:00",
                @"林川", @"SONY", @"ILCE-7M4", @"SN-A1", @"FE 24-70mm F2.8 GM II");
    FixturePNG(@"10-混合格式", @"MIX_8002.png");
    FixtureCopy(@"10-混合格式", @"MIX_8001.jpg", @"10-混合格式", @"MIX_8003.nef");
    FixtureEmpty(@"10-混合格式", @"MIX_8004.mov");
    FixtureEmpty(@"10-混合格式", @"MIX_8005.mp3");
    FixtureText(@"10-混合格式", @"MIX_8006.lrf", @"LRF preview placeholder\n");

    // 11 多人 + 无身份混合：触发未知身份里的「无作者信息」行
    FixtureJPEG(@"11-多人-无身份混合", @"A_9101.jpg", 9101, @"2026:05:20 09:00:00",
                @"林川", @"SONY", @"ILCE-7M4", @"SN-A1", @"FE 24-70mm F2.8 GM II");
    FixtureJPEG(@"11-多人-无身份混合", @"B_9102.jpg", 9102, @"2026:05:20 09:01:00",
                @"阿哲", @"Canon", @"EOS R5", @"SN-B2", @"RF 24-70mm F2.8 L IS USM");
    FixturePNG(@"11-多人-无身份混合", @"NOEXIF_9103.png");
    FixtureEmpty(@"11-多人-无身份混合", @"VIDEO_9104.MOV");
    FixtureEmpty(@"11-多人-无身份混合", @"AUDIO_9105.mp3");

    // 12 按上级文件夹归类：单作者文件夹里的无信息文件 + 多人文件夹
    FixtureJPEG(@"12-按文件夹归类/林川", @"A_9201.jpg", 9201, @"2026:05:20 10:00:00",
                @"林川", @"SONY", @"ILCE-7M4", @"SN-A1", @"FE 24-70mm F2.8 GM II");
    FixtureJPEGNoMeta(@"12-按文件夹归类/林川", @"A_9202.jpg", 9202);
    FixtureJPEG(@"12-按文件夹归类/阿哲", @"B_9301.jpg", 9301, @"2026:05:20 10:05:00",
                @"阿哲", @"Canon", @"EOS R5", @"SN-B2", @"RF 24-70mm F2.8 L IS USM");
    FixtureJPEGNoMeta(@"12-按文件夹归类/阿哲", @"B_9302.jpg", 9302);
    FixtureJPEG(@"12-按文件夹归类/合影", @"C_9401.jpg", 9401, @"2026:05:20 10:10:00",
                @"林川", @"SONY", @"ILCE-7M4", @"SN-A1", @"FE 24-70mm F2.8 GM II");
    FixtureJPEG(@"12-按文件夹归类/合影", @"C_9402.jpg", 9402, @"2026:05:20 10:11:00",
                @"阿哲", @"Canon", @"EOS R5", @"SN-B2", @"RF 24-70mm F2.8 L IS USM");
    FixtureJPEGNoMeta(@"12-按文件夹归类/合影", @"C_9403.jpg", 9403);

    // 13 确认弹窗专用：只有两个单人文件夹，没有多人文件夹
    FixtureJPEG(@"13-确认弹窗专用/林川", @"LIN_0001.jpg", 9501, @"2026:05:20 11:00:00",
                @"林川", @"SONY", @"ILCE-7M4", @"SN-A1", @"FE 24-70mm F2.8 GM II");
    FixtureJPEGNoMeta(@"13-确认弹窗专用/林川", @"LIN_0002.jpg", 9502);
    FixtureJPEG(@"13-确认弹窗专用/阿哲", @"ZHE_0001.jpg", 9601, @"2026:05:20 11:05:00",
                @"阿哲", @"Canon", @"EOS R5", @"SN-B2", @"RF 24-70mm F2.8 L IS USM");
    FixtureJPEGNoMeta(@"13-确认弹窗专用/阿哲", @"ZHE_0002.jpg", 9602);

    printf("created fixtures in %s\n", base.UTF8String);
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc >= 2 && strcmp(argv[1], "--fixtures") == 0) {
            if (argc < 3) {
                fprintf(stderr, "usage: mkphotos --fixtures <output-dir>\n");
                return 2;
            }
            MakeFixtures([NSString stringWithUTF8String:argv[2]]);
            return 0;
        }
        if (argc < 2) {
            fprintf(stderr, "usage: mkphotos <output-dir> [artist] | --fixtures <output-dir>\n");
            return 2;
        }
        NSString *dir = [NSString stringWithUTF8String:argv[1]];
        NSString *artist = argc > 2 ? [NSString stringWithUTF8String:argv[2]] : @"张三";
        NSFileManager *fm = [NSFileManager defaultManager];
        [fm createDirectoryAtPath:[dir stringByAppendingPathComponent:@"A"]
      withIntermediateDirectories:YES attributes:nil error:NULL];
        [fm createDirectoryAtPath:[dir stringByAppendingPathComponent:@"B"]
      withIntermediateDirectories:YES attributes:nil error:NULL];

        WriteJPEG([dir stringByAppendingPathComponent:@"A/IMG_0001.jpg"],
                  @"2026:10:19 09:12:30", 1, artist, @"SONY", @"ILCE-7M4", @"SN-7788",
                  @"FE 24-70mm F2.8 GM II", YES);
        WriteJPEG([dir stringByAppendingPathComponent:@"A/IMG_0002.jpg"],
                  @"2026:10:19 10:30:00", 2, artist, @"SONY", @"ILCE-7M4", @"SN-7788",
                  @"FE 24-70mm F2.8 GM II", YES);
        WriteJPEG([dir stringByAppendingPathComponent:@"A/IMG_0003.jpg"],
                  @"2026:10:19 18:40:12", 3, artist, @"SONY", @"ILCE-7M4", @"SN-7788",
                  @"FE 24-70mm F2.8 GM II", YES);
        WriteJPEG([dir stringByAppendingPathComponent:@"A/IMG_0004.jpg"],
                  @"2026:10:18 20:05:00", 4, artist, @"SONY", @"ILCE-7M4", @"SN-7788",
                  @"FE 24-70mm F2.8 GM II", YES);
        WritePNG([dir stringByAppendingPathComponent:@"A/screenshot.png"]);
        WriteJPEG([dir stringByAppendingPathComponent:@"B/IMG_0001.jpg"],
                  @"2026:10:19 12:00:00", 9, artist, @"SONY", @"ILCE-7M4", @"SN-7788",
                  @"FE 24-70mm F2.8 GM II", YES);
        [fm copyItemAtPath:[dir stringByAppendingPathComponent:@"A/IMG_0002.jpg"]
                    toPath:[dir stringByAppendingPathComponent:@"B/IMG_0002 copy.jpg"]
                     error:NULL];
        printf("created test photos in %s\n", dir.UTF8String);
    }
    return 0;
}
