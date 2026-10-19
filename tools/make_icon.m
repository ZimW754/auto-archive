// 生成应用图标（1024×1024 PNG）。仅构建时使用。
// clang -fobjc-arc -framework Cocoa -o /tmp/make_icon tools/make_icon.m

#import <Cocoa/Cocoa.h>

static NSColor *Hex(unsigned rgb, CGFloat alpha) {
    return [NSColor colorWithSRGBRed:((rgb >> 16) & 0xFF) / 255.0
                               green:((rgb >> 8) & 0xFF) / 255.0
                                blue:(rgb & 0xFF) / 255.0
                               alpha:alpha];
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc < 2) {
            fprintf(stderr, "usage: make_icon <output.png>\n");
            return 2;
        }
        const NSInteger S = 1024;
        NSBitmapImageRep *rep = [[NSBitmapImageRep alloc] initWithBitmapDataPlanes:NULL
                                                                        pixelsWide:S
                                                                        pixelsHigh:S
                                                                     bitsPerSample:8
                                                                   samplesPerPixel:4
                                                                          hasAlpha:YES
                                                                          isPlanar:NO
                                                                    colorSpaceName:NSCalibratedRGBColorSpace
                                                                       bytesPerRow:0
                                                                      bitsPerPixel:0];
        NSGraphicsContext *ctx = [NSGraphicsContext graphicsContextWithBitmapImageRep:rep];
        [NSGraphicsContext saveGraphicsState];
        [NSGraphicsContext setCurrentContext:ctx];

        // 背景
        NSRect bgRect = NSMakeRect(40, 40, 944, 944);
        NSBezierPath *bg = [NSBezierPath bezierPathWithRoundedRect:bgRect xRadius:214 yRadius:214];
        NSGradient *bgGradient = [[NSGradient alloc] initWithColors:@[
            Hex(0xFFC978, 1.0), Hex(0xF9794F, 1.0)
        ]];
        [bgGradient drawInBezierPath:bg angle:-90];

        // 文件夹阴影
        NSShadow *shadow = [NSShadow new];
        shadow.shadowColor = [NSColor colorWithCalibratedWhite:0.35 alpha:0.35];
        shadow.shadowBlurRadius = 26;
        shadow.shadowOffset = NSMakeSize(0, -14);

        // 文件夹背板 + 标签页
        [shadow set];
        NSColor *paper = [NSColor colorWithSRGBRed:0.988 green:0.984 blue:0.972 alpha:1.0];
        [paper setFill];
        [[NSBezierPath bezierPathWithRoundedRect:NSMakeRect(172, 330, 680, 360)
                                         xRadius:44 yRadius:44] fill];
        [[NSBezierPath bezierPathWithRoundedRect:NSMakeRect(172, 618, 268, 116)
                                         xRadius:38 yRadius:38] fill];

        // 从文件夹里露出一张照片
        [NSGraphicsContext saveGraphicsState];
        NSAffineTransform *t = [NSAffineTransform transform];
        [t translateXBy:520 yBy:600];
        [t rotateByDegrees:-7];
        [t translateXBy:-520 yBy:-600];
        [t concat];

        NSRect card = NSMakeRect(316, 478, 442, 348);
        NSShadow *cardShadow = [NSShadow new];
        cardShadow.shadowColor = [NSColor colorWithCalibratedWhite:0.3 alpha:0.30];
        cardShadow.shadowBlurRadius = 18;
        cardShadow.shadowOffset = NSMakeSize(0, -8);
        [cardShadow set];
        [[NSColor whiteColor] setFill];
        [[NSBezierPath bezierPathWithRoundedRect:card xRadius:26 yRadius:26] fill];

        NSRect photo = NSInsetRect(card, 20, 20);
        NSBezierPath *photoPath = [NSBezierPath bezierPathWithRoundedRect:photo xRadius:12 yRadius:12];
        [photoPath addClip];
        NSGradient *sky = [[NSGradient alloc] initWithColors:@[
            Hex(0x8CC7FF, 1.0), Hex(0xD9ECFF, 1.0)
        ]];
        [sky drawInRect:photo angle:-90];
        // 太阳
        [[NSColor colorWithSRGBRed:1.0 green:0.94 blue:0.72 alpha:1.0] setFill];
        [[NSBezierPath bezierPathWithOvalInRect:NSMakeRect(photo.origin.x + 268,
                                                          photo.origin.y + 196, 92, 92)] fill];
        // 山
        NSBezierPath *mountain = [NSBezierPath bezierPath];
        [mountain moveToPoint:NSMakePoint(photo.origin.x - 10, photo.origin.y + 10)];
        [mountain lineToPoint:NSMakePoint(photo.origin.x + 150, photo.origin.y + 196)];
        [mountain lineToPoint:NSMakePoint(photo.origin.x + 300, photo.origin.y + 40)];
        [mountain lineToPoint:NSMakePoint(photo.origin.x + 420, photo.origin.y + 176)];
        [mountain lineToPoint:NSMakePoint(photo.origin.x + 470, photo.origin.y + 10)];
        [mountain closePath];
        [Hex(0x3F8F6B, 1.0) setFill];
        [mountain fill];
        [NSGraphicsContext restoreGraphicsState];

        // 文件夹前板（遮住照片下半部分）
        NSShadow *frontShadow = [NSShadow new];
        frontShadow.shadowColor = [NSColor colorWithCalibratedWhite:0.3 alpha:0.30];
        frontShadow.shadowBlurRadius = 24;
        frontShadow.shadowOffset = NSMakeSize(0, 10);
        [frontShadow set];

        NSRect frontRect = NSMakeRect(172, 244, 680, 372);
        NSBezierPath *front = [NSBezierPath bezierPathWithRoundedRect:frontRect xRadius:46 yRadius:46];
        NSGradient *frontGradient = [[NSGradient alloc] initWithColors:@[
            [NSColor colorWithSRGBRed:1.0 green:1.0 blue:1.0 alpha:1.0],
            [NSColor colorWithSRGBRed:0.953 green:0.945 blue:0.925 alpha:1.0]
        ]];
        [frontGradient drawInBezierPath:front angle:-90];

        [NSGraphicsContext restoreGraphicsState];

        NSData *png = [rep representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
        if (![png writeToFile:[NSString stringWithUTF8String:argv[1]] atomically:YES]) {
            fprintf(stderr, "write failed\n");
            return 1;
        }
    }
    return 0;
}
