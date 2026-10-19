// 自动归档 — 按标准自动建立归档目录
// 原生 AppKit 单文件实现，无第三方依赖。
// 构建方式见 build.sh

#import <Cocoa/Cocoa.h>
#import <ImageIO/ImageIO.h>
#import <CommonCrypto/CommonDigest.h>

static NSString *const kAppTitle = @"自动归档";
static NSString *const kAppVersion = @"1.22.7";
static NSString *const kDeveloper = @"ZimW";
static NSString *const kKeyRoot  = @"root";
static NSString *const kOriginalPhotoName = @"（原始照片）";
static NSString *const kOriginalVideoName = @"（原始视频）";
static NSString *const kUnknownAuthorName = @"未标注";
static NSString *const kKeyEvent = @"event";
static NSString *const kKeyMode  = @"mode";
static NSString *const kKeySubs  = @"subs";              // 旧版：逗号分隔
static NSString *const kKeySubsSelected = @"subsSelected";  // 标签选择（JSON 数组）
static NSString *const kKeySubRecents = @"subfolderRecents"; // 最近使用
static NSString *const kKeySignOn = @"signOn";
static NSString *const kKeySignText = @"signText";
static NSString *const kKeySignRules = @"signRules";
static NSString *const kKeyManualSignOn = @"manualSignOn";
static NSString *const kKeyManualSignText = @"manualSignText";
static NSString *const kKeyAutoSignOn = @"autoSignOn";
static NSString *const kKeyMultiPerson = @"multiPerson";
static NSString *const kKeyAutoDate = @"autoDate";
static NSString *const kKeyLastDate = @"lastDate";
static NSString *const kKeyTagOn = @"tagOn";
static NSString *const kKeyTagText = @"tagText";
static NSString *const kKeyVerifyOn = @"verifyOn";
static NSString *const kKeyVerifyKind = @"verifyKind";


#pragma mark - 校验哈希

#define XXH_PRIME64_1 0x9E3779B185EBCA87ULL
#define XXH_PRIME64_2 0xC2B2AE3D27D4EB4FULL
#define XXH_PRIME64_3 0x165667B19E3779F9ULL
#define XXH_PRIME64_4 0x85EBCA77C2B2AE63ULL
#define XXH_PRIME64_5 0x27D4EB2F165667C5ULL

static uint64_t XXHRotl64(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}

static uint64_t XXHRead64(const unsigned char *p) {
    uint64_t value;
    memcpy(&value, p, 8);
    return value;
}

static uint32_t XXHRead32(const unsigned char *p) {
    uint32_t value;
    memcpy(&value, p, 4);
    return value;
}

static uint64_t XXHRound(uint64_t acc, uint64_t input) {
    acc += input * XXH_PRIME64_2;
    acc = XXHRotl64(acc, 31);
    acc *= XXH_PRIME64_1;
    return acc;
}

static uint64_t XXHMergeRound(uint64_t acc, uint64_t value) {
    value = XXHRound(0, value);
    acc ^= value;
    acc = acc * XXH_PRIME64_1 + XXH_PRIME64_4;
    return acc;
}

typedef struct {
    uint64_t total;
    uint64_t v1, v2, v3, v4;
    unsigned char mem[32];
    size_t memsize;
    uint64_t seed;
} XXH64State;

static void XXH64Reset(XXH64State *state, uint64_t seed) {
    state->seed = seed;
    state->v1 = seed + XXH_PRIME64_1 + XXH_PRIME64_2;
    state->v2 = seed + XXH_PRIME64_2;
    state->v3 = seed;
    state->v4 = seed - XXH_PRIME64_1;
    state->total = 0;
    state->memsize = 0;
}

static void XXH64Stripe(XXH64State *state, const unsigned char *p) {
    state->v1 = XXHRound(state->v1, XXHRead64(p));
    state->v2 = XXHRound(state->v2, XXHRead64(p + 8));
    state->v3 = XXHRound(state->v3, XXHRead64(p + 16));
    state->v4 = XXHRound(state->v4, XXHRead64(p + 24));
}

static void XXH64Update(XXH64State *state, const void *data, size_t length) {
    const unsigned char *p = (const unsigned char *)data;
    state->total += length;

    if (state->memsize + length < 32) {
        memcpy(state->mem + state->memsize, p, length);
        state->memsize += length;
        return;
    }
    if (state->memsize) {
        size_t fill = 32 - state->memsize;
        memcpy(state->mem + state->memsize, p, fill);
        XXH64Stripe(state, state->mem);
        p += fill;
        length -= fill;
        state->memsize = 0;
    }
    while (length >= 32) {
        XXH64Stripe(state, p);
        p += 32;
        length -= 32;
    }
    if (length) {
        memcpy(state->mem, p, length);
        state->memsize = length;
    }
}

static uint64_t XXH64Digest(const XXH64State *state) {
    uint64_t h;
    if (state->total >= 32) {
        h = XXHRotl64(state->v1, 1) + XXHRotl64(state->v2, 7) +
            XXHRotl64(state->v3, 12) + XXHRotl64(state->v4, 18);
        h = XXHMergeRound(h, state->v1);
        h = XXHMergeRound(h, state->v2);
        h = XXHMergeRound(h, state->v3);
        h = XXHMergeRound(h, state->v4);
    } else {
        h = state->seed + XXH_PRIME64_5;
    }
    h += state->total;

    const unsigned char *p = state->mem;
    size_t length = state->memsize;
    while (length >= 8) {
        h ^= XXHRound(0, XXHRead64(p));
        h = XXHRotl64(h, 27) * XXH_PRIME64_1 + XXH_PRIME64_4;
        p += 8;
        length -= 8;
    }
    if (length >= 4) {
        h ^= (uint64_t)XXHRead32(p) * XXH_PRIME64_1;
        h = XXHRotl64(h, 23) * XXH_PRIME64_2 + XXH_PRIME64_3;
        p += 4;
        length -= 4;
    }
    while (length > 0) {
        h ^= (uint64_t)(*p) * XXH_PRIME64_5;
        h = XXHRotl64(h, 11) * XXH_PRIME64_1;
        p++;
        length--;
    }
    h ^= h >> 33;
    h *= XXH_PRIME64_2;
    h ^= h >> 29;
    h *= XXH_PRIME64_3;
    h ^= h >> 32;
    return h;
}

/// kind: 0 = xxHash64, 1 = MD5
static NSString *HashFileAtURL(NSURL *url, NSInteger kind) {
    NSFileHandle *handle = [NSFileHandle fileHandleForReadingFromURL:url error:NULL];
    if (!handle) return nil;

    if (kind == 1) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        CC_MD5_CTX ctx;
        CC_MD5_Init(&ctx);
        while (YES) {
            @autoreleasepool {
                NSData *chunk = [handle readDataOfLength:1024 * 1024];
                if (!chunk.length) break;
                CC_MD5_Update(&ctx, chunk.bytes, (CC_LONG)chunk.length);
            }
        }
        unsigned char digest[CC_MD5_DIGEST_LENGTH];
        CC_MD5_Final(digest, &ctx);
#pragma clang diagnostic pop
        NSMutableString *hex = [NSMutableString stringWithCapacity:32];
        for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) [hex appendFormat:@"%02x", digest[i]];
        [handle closeFile];
        return hex;
    }

    XXH64State state;
    XXH64Reset(&state, 0);
    while (YES) {
        @autoreleasepool {
            NSData *chunk = [handle readDataOfLength:1024 * 1024];
            if (!chunk.length) break;
            XXH64Update(&state, chunk.bytes, chunk.length);
        }
    }
    [handle closeFile];
    return [NSString stringWithFormat:@"%016llx", (unsigned long long)XXH64Digest(&state)];
}

#pragma mark - 文档渲染

static NSString *StripInlineMarkdown(NSString *text) {
    NSString *s = text ?: @"";
    s = [s stringByReplacingOccurrencesOfString:@"**" withString:@""];
    s = [s stringByReplacingOccurrencesOfString:@"`" withString:@""];
    NSRegularExpression *regex =
        [NSRegularExpression regularExpressionWithPattern:@"\\[([^\\]]+)\\]\\([^\\)]+\\)"
                                                  options:0 error:NULL];
    s = [regex stringByReplacingMatchesInString:s
                                        options:0
                                          range:NSMakeRange(0, s.length)
                                   withTemplate:@"$1"];
    return s;
}

static NSAttributedString *RenderMarkdownDocument(NSString *markdown) {
    NSMutableAttributedString *result = [[NSMutableAttributedString alloc] init];
    NSArray<NSString *> *lines = [(markdown ?: @"") componentsSeparatedByString:@"\n"];

    void (^append)(NSString *, NSFont *, NSColor *, CGFloat, BOOL) =
        ^(NSString *text, NSFont *font, NSColor *color, CGFloat indent, BOOL bullet) {
        NSMutableParagraphStyle *style = [NSMutableParagraphStyle new];
        style.paragraphSpacing = 4.0;
        style.lineSpacing = 1.5;
        if (indent > 0) {
            style.headIndent = indent;
            style.firstLineHeadIndent = bullet ? 0 : indent;
        }
        NSString *body = bullet
            ? [@"•  " stringByAppendingString:text]
            : text;
        NSAttributedString *piece =
            [[NSAttributedString alloc] initWithString:[body stringByAppendingString:@"\n"]
                                            attributes:@{
                                                NSFontAttributeName: font,
                                                NSForegroundColorAttributeName: color,
                                                NSParagraphStyleAttributeName: style
                                            }];
        [result appendAttributedString:piece];
    };

    BOOL inCodeBlock = NO;
    for (NSString *raw in lines) {
        NSString *line = [raw stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        if ([line hasPrefix:@"```"]) {
            inCodeBlock = !inCodeBlock;
            continue;
        }
        if (inCodeBlock) {
            append(line, [NSFont monospacedSystemFontOfSize:11.5 weight:NSFontWeightRegular],
                   [NSColor secondaryLabelColor], 12, NO);
            continue;
        }
        if (!line.length) {
            append(@"", [NSFont systemFontOfSize:5], [NSColor clearColor], 0, NO);
            continue;
        }
        if ([line hasPrefix:@"|---"] || [line hasPrefix:@"| ---"] || [line hasPrefix:@"|:--"]) continue;

        if ([line hasPrefix:@"# "]) {
            append(StripInlineMarkdown([line substringFromIndex:2]),
                   [NSFont systemFontOfSize:20 weight:NSFontWeightBold], [NSColor labelColor], 0, NO);
        } else if ([line hasPrefix:@"## "]) {
            append(StripInlineMarkdown([line substringFromIndex:3]),
                   [NSFont systemFontOfSize:15 weight:NSFontWeightSemibold], [NSColor labelColor], 0, NO);
        } else if ([line hasPrefix:@"### "]) {
            append(StripInlineMarkdown([line substringFromIndex:4]),
                   [NSFont systemFontOfSize:13 weight:NSFontWeightSemibold], [NSColor labelColor], 0, NO);
        } else if ([line hasPrefix:@"- "]) {
            append(StripInlineMarkdown([line substringFromIndex:2]),
                   [NSFont systemFontOfSize:12.5], [NSColor labelColor], 16, YES);
        } else if ([line hasPrefix:@"|"]) {
            NSMutableArray *cells = [NSMutableArray array];
            for (NSString *cell in [line componentsSeparatedByString:@"|"]) {
                NSString *clean = [cell stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                if (clean.length) [cells addObject:StripInlineMarkdown(clean)];
            }
            append([cells componentsJoinedByString:@"    "],
                   [NSFont systemFontOfSize:12], [NSColor secondaryLabelColor], 12, NO);
        } else {
            append(StripInlineMarkdown(line),
                   [NSFont systemFontOfSize:12.5], [NSColor labelColor], 0, NO);
        }
    }
    return result;
}

#pragma mark - 基础工具

static NSString *Trim(NSString *s) {
    return [s stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
}

static NSString *AbbreviatePath(NSString *p) {
    NSString *home = NSHomeDirectory();
    if ([p isEqualToString:home]) return @"~";
    NSString *prefix = [home stringByAppendingString:@"/"];
    if ([p hasPrefix:prefix]) return [@"~" stringByAppendingString:[p substringFromIndex:home.length]];
    return p;
}

static void ShowError(NSWindow *window, NSString *title, NSString *message) {
    NSAlert *alert = [NSAlert new];
    alert.messageText = title;
    alert.informativeText = message ?: @"";
    alert.alertStyle = NSAlertStyleWarning;
    [alert addButtonWithTitle:@"好"];
    if (window) {
        [alert beginSheetModalForWindow:window completionHandler:nil];
    } else {
        [alert runModal];
    }
}

// 去掉文件名中非法的字符，保留中文全角括号等
static NSString *SanitizeComponent(NSString *raw) {
    NSString *s = Trim(raw ?: @"");
    NSCharacterSet *bad = [NSCharacterSet characterSetWithCharactersInString:@"/\\:*?\"<>|\r\n\t"];
    s = [[s componentsSeparatedByCharactersInSet:bad] componentsJoinedByString:@""];
    while ([s hasPrefix:@"."]) s = [s substringFromIndex:1];
    while ([s containsString:@"  "]) s = [s stringByReplacingOccurrencesOfString:@"  " withString:@" "];
    s = Trim(s);
    if (s.length > 90) s = [s substringToIndex:90];
    s = Trim(s);
    return s;
}

static NSArray<NSString *> *DefaultSubfolders(void) {
    return @[ @"（筛选）", @"（收集）" ];
}

static NSArray<NSString *> *ParseSubfolders(NSString *raw) {
    NSString *s = raw ?: @"";
    NSArray *parts = [s componentsSeparatedByCharactersInSet:
                      [NSCharacterSet characterSetWithCharactersInString:@"，,、;；\n"]];
    NSMutableArray *out = [NSMutableArray array];
    for (NSString *p in parts) {
        NSString *c = SanitizeComponent(p);
        if (c.length) [out addObject:c];
    }
    return out;
}

static NSDateFormatter *DayFormatter(void) {
    static NSDateFormatter *f;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        f = [NSDateFormatter new];
        f.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
        f.dateFormat = @"yy.MM.dd";
    });
    return f;
}

static NSString *FolderBaseName(NSDate *date, NSString *event) {
    NSString *day = [DayFormatter() stringFromDate:date ?: [NSDate date]];
    NSString *name = SanitizeComponent(event);
    return [day stringByAppendingString:name];
}

static NSDate *DateFromEXIFString(NSString *s) {
    if (![s isKindOfClass:[NSString class]] || s.length < 10) return nil;
    static NSDateFormatter *a, *b;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        a = [NSDateFormatter new];
        a.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
        a.dateFormat = @"yyyy:MM:dd HH:mm:ss";
        a.timeZone = [NSTimeZone localTimeZone];
        b = [NSDateFormatter new];
        b.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
        b.dateFormat = @"yyyy-MM-dd HH:mm:ss";
        b.timeZone = [NSTimeZone localTimeZone];
    });
    NSDate *d = [a dateFromString:s] ?: [b dateFromString:s];
    if (!d) return nil;
    if (d.timeIntervalSince1970 <= 0) return nil;
    return d;
}

#pragma mark - 媒体文件与拍摄时间

static NSArray<NSString *> *ImageExtensionList(void) {
    return @[ @"jpg", @"jpeg", @"png", @"heic", @"heif", @"tif", @"tiff",
              @"bmp", @"gif", @"webp", @"avif" ];
}

static NSArray<NSString *> *RawExtensionList(void) {
    return @[ @"dng", @"cr2", @"cr3", @"nef", @"arw", @"raf", @"rw2", @"orf",
              @"pef", @"srw", @"x3f", @"rwl", @"raw", @"3fr", @"mef", @"mos",
              @"mrw", @"nrw", @"sr2", @"rwz", @"iiq", @"kdc", @"dcr", @"erf",
              @"mdc", @"ptx" ];
}

static NSArray<NSString *> *VideoExtensionList(void) {
    return @[ @"mov", @"mp4", @"m4v", @"avi", @"mkv", @"mts", @"m2ts",
              @"mpg", @"mpeg", @"wmv", @"webm", @"3gp" ];
}

static NSArray<NSString *> *AudioExtensionList(void) {
    return @[ @"mp3", @"wav", @"aif", @"aiff", @"m4a", @"aac", @"flac",
              @"ogg", @"wma", @"caf", @"ape" ];
}

static NSString *const kFileTypesImageKey = @"fileTypes.image";
static NSString *const kFileTypesRawKey = @"fileTypes.raw";
static NSString *const kFileTypesVideoKey = @"fileTypes.video";
static NSString *const kFileTypesAudioKey = @"fileTypes.audio";
static NSString *const kFileTypesPreviewKey = @"fileTypes.preview";
static NSString *const kTagPresetsKey = @"tag.presets";

static NSArray<NSString *> *DefaultTagPresets(void) {
    return @[ @"拷卡", @"微信", @"QQ", @"云盘" ];
}

static NSArray<NSString *> *NormalizeTagPresets(NSArray *input) {
    NSMutableArray<NSString *> *out = [NSMutableArray array];
    NSCharacterSet *trimSet = [NSCharacterSet whitespaceAndNewlineCharacterSet];
    for (id value in input) {
        if (![value isKindOfClass:[NSString class]]) continue;
        NSString *tag = [(NSString *)value stringByTrimmingCharactersInSet:trimSet];
        if (!tag.length) continue;
        if (![out containsObject:tag]) [out addObject:tag];
    }
    return out;
}

static NSArray<NSString *> *SourceTagPresets(void) {
    id saved = [[NSUserDefaults standardUserDefaults] objectForKey:kTagPresetsKey];
    if ([saved isKindOfClass:[NSArray class]]) {
        NSArray *normalized = NormalizeTagPresets(saved);
        if (normalized.count) return normalized;
    }
    return DefaultTagPresets();
}

static NSString *const kSubfolderPresetsKey = @"subfolder.presets";

static NSArray<NSString *> *SubfolderPresets(void) {
    id saved = [[NSUserDefaults standardUserDefaults] objectForKey:kSubfolderPresetsKey];
    if ([saved isKindOfClass:[NSArray class]]) {
        NSArray *normalized = NormalizeTagPresets(saved);
        if (normalized.count) return normalized;
    }
    return DefaultSubfolders();
}

static NSArray<NSString *> *TokenFieldValues(NSTokenField *field);

static NSArray<NSString *> *ExtensionsFromField(NSTokenField *field, NSString **message) {
    NSArray<NSString *> *values = TokenFieldValues(field);
    NSMutableArray<NSString *> *out = [NSMutableArray array];
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:
                               @"abcdefghijklmnopqrstuvwxyz0123456789"];
    for (NSString *value in values) {
        NSString *ext = value.lowercaseString;
        while ([ext hasPrefix:@"."]) ext = [ext substringFromIndex:1];
        if (!ext.length) continue;
        if ([[ext stringByTrimmingCharactersInSet:allowed] length]) {
            if (message) *message = [NSString stringWithFormat:@"扩展名「%@」只能包含字母和数字", ext];
            return nil;
        }
        if (![out containsObject:ext]) [out addObject:ext];
    }
    return out;
}

static NSArray<NSString *> *TokenFieldValues(NSTokenField *field) {
    id value = field.objectValue;
    NSArray *list = nil;
    if ([value isKindOfClass:[NSArray class]]) list = value;
    else if ([value isKindOfClass:[NSString class]] && [(NSString *)value length]) list = @[value];
    return NormalizeTagPresets(list ?: @[]);
}


static NSArray<NSString *> *PreviewExtensionList(void) {
    return @[ @"lrf" ];
}

static NSArray<NSString *> *NormalizeExtensionList(NSArray *input) {
    NSMutableArray<NSString *> *out = [NSMutableArray array];
    NSCharacterSet *trimSet = [NSCharacterSet whitespaceAndNewlineCharacterSet];
    for (id value in input) {
        if (![value isKindOfClass:[NSString class]]) continue;
        NSString *ext = [[(NSString *)value lowercaseString] stringByTrimmingCharactersInSet:trimSet];
        while ([ext hasPrefix:@"."]) ext = [ext substringFromIndex:1];
        if (!ext.length) continue;
        if (![out containsObject:ext]) [out addObject:ext];
    }
    return out;
}

static NSArray<NSString *> *SavedExtensionList(NSString *key, NSArray<NSString *> *fallback) {
    id saved = [[NSUserDefaults standardUserDefaults] objectForKey:key];
    if ([saved isKindOfClass:[NSArray class]]) return NormalizeExtensionList(saved);
    return NormalizeExtensionList(fallback);
}

static NSLock *ExtensionLock(void) {
    static NSLock *lock;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ lock = [NSLock new]; });
    return lock;
}

static NSDictionary<NSString *, NSSet<NSString *> *> *BuildExtensionSets(void) {
    NSSet *image = [NSSet setWithArray:SavedExtensionList(kFileTypesImageKey, ImageExtensionList())];
    NSSet *raw = [NSSet setWithArray:SavedExtensionList(kFileTypesRawKey, RawExtensionList())];
    NSSet *video = [NSSet setWithArray:SavedExtensionList(kFileTypesVideoKey, VideoExtensionList())];
    NSSet *audio = [NSSet setWithArray:SavedExtensionList(kFileTypesAudioKey, AudioExtensionList())];
    NSSet *preview = [NSSet setWithArray:SavedExtensionList(kFileTypesPreviewKey, PreviewExtensionList())];
    NSMutableSet *photo = [image mutableCopy];
    [photo unionSet:raw];
    return @{ @"image": image, @"raw": raw, @"video": video,
              @"audio": audio, @"preview": preview, @"photo": [photo copy] };
}

static NSDictionary<NSString *, NSSet<NSString *> *> *gExtensionSets;

static NSSet<NSString *> *ExtensionSet(NSString *key) {
    NSLock *lock = ExtensionLock();
    [lock lock];
    if (!gExtensionSets) gExtensionSets = BuildExtensionSets();
    NSSet *set = gExtensionSets[key] ?: [NSSet set];
    [lock unlock];
    return set;
}

static void ReloadExtensionSets(void) {
    NSLock *lock = ExtensionLock();
    [lock lock];
    gExtensionSets = BuildExtensionSets();
    [lock unlock];
}

static NSSet<NSString *> *PhotoExtensions(void) { return ExtensionSet(@"photo"); }
static NSSet<NSString *> *MovieExtensions(void) { return ExtensionSet(@"video"); }
static NSSet<NSString *> *ImageExtensions(void) { return ExtensionSet(@"image"); }
static NSSet<NSString *> *RawExtensions(void) { return ExtensionSet(@"raw"); }
static NSSet<NSString *> *AudioExtensions(void) { return ExtensionSet(@"audio"); }
static NSSet<NSString *> *PreviewExtensions(void) { return ExtensionSet(@"preview"); }

/// 0=图片 1=RAW 2=视频 3=音频，-1=其他
static NSInteger CategoryForExtension(NSString *extension) {
    NSString *ext = extension.lowercaseString;
    if (!ext.length) return -1;
    if ([RawExtensions() containsObject:ext]) return 1;
    if ([ImageExtensions() containsObject:ext]) return 0;
    if ([MovieExtensions() containsObject:ext]) return 2;
    if ([AudioExtensions() containsObject:ext]) return 3;
    return -1;
}

static NSArray<NSString *> *CategoryTitles(void) {
    return @[ @"图片", @"RAW", @"视频", @"音频" ];
}

static BOOL IsMediaURL(NSURL *url) {
    NSString *ext = url.pathExtension.lowercaseString;
    return [PhotoExtensions() containsObject:ext] ||
           [MovieExtensions() containsObject:ext] ||
           [AudioExtensions() containsObject:ext];
}

typedef NS_ENUM(NSInteger, CaptureSource) {
    CaptureSourceEXIF = 0,
    CaptureSourceFileSystem = 1
};

typedef NS_ENUM(NSInteger, AutoDateResult) {
    AutoDateResultNone = 0,
    AutoDateResultAdopted,
    AutoDateResultMismatch
};

static NSString *DayKey(NSDate *date) {
    static NSDateFormatter *formatter;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        formatter = [NSDateFormatter new];
        formatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
        formatter.dateFormat = @"yyyy-MM-dd";
        formatter.timeZone = [NSTimeZone localTimeZone];
    });
    return date ? [formatter stringFromDate:date] : @"";
}

/// 一张照片的元数据：拍摄时间 + 能辨别身份的信息。
@interface PhotoMetadata : NSObject
@property (nonatomic) NSDate *date;
@property (nonatomic) CaptureSource dateSource;
@property (nonatomic, copy) NSString *artist;      // 作者 / 相机所有者 / IPTC 署名
@property (nonatomic, copy) NSString *copyright;
@property (nonatomic, copy) NSString *make;
@property (nonatomic, copy) NSString *model;
@property (nonatomic, copy) NSString *lens;
@property (nonatomic, copy) NSString *bodySerial;
@property (nonatomic, copy) NSString *lensSerial;
@property (nonatomic, copy) NSString *uniqueID;
- (NSArray<NSString *> *)identityValues;
@end

@implementation PhotoMetadata

- (NSArray<NSString *> *)identityValues {
    NSMutableArray *values = [NSMutableArray array];
    for (NSString *v in @[ self.artist ?: @"", self.model ?: @"",
                           self.bodySerial ?: @"", self.lensSerial ?: @"" ]) {
        if (v.length) [values addObject:v];
    }
    return values;
}

@end

static NSString *CleanString(id value) {
    if (![value isKindOfClass:[NSString class]]) return nil;
    NSString *s = Trim(value);
    if (!s.length) return nil;
    if ([s caseInsensitiveCompare:@"null"] == NSOrderedSame) return nil;
    return s;
}

static NSString *DictString(NSDictionary *dict, CFStringRef key) {
    if (![dict isKindOfClass:[NSDictionary class]]) return nil;
    return CleanString(dict[(__bridge NSString *)key]);
}

static PhotoMetadata *PhotoMetadataForURL(NSURL *url) {
    NSDictionary *opts = @{ (__bridge NSString *)kCGImageSourceShouldCache : @NO };
    CGImageSourceRef src = CGImageSourceCreateWithURL((__bridge CFURLRef)url,
                                                      (__bridge CFDictionaryRef)opts);
    if (!src) return nil;
    CFDictionaryRef propsRef = CGImageSourceCopyPropertiesAtIndex(src, 0,
                                                                 (__bridge CFDictionaryRef)opts);
    CFRelease(src);
    NSDictionary *props = CFBridgingRelease(propsRef);
    if (![props isKindOfClass:[NSDictionary class]]) return nil;

    NSDictionary *exif = props[(__bridge NSString *)kCGImagePropertyExifDictionary];
    NSDictionary *tiff = props[(__bridge NSString *)kCGImagePropertyTIFFDictionary];
    NSDictionary *aux = props[(__bridge NSString *)kCGImagePropertyExifAuxDictionary];
    NSDictionary *iptc = props[(__bridge NSString *)kCGImagePropertyIPTCDictionary];

    PhotoMetadata *meta = [PhotoMetadata new];
    NSString *dateString = DictString(exif, kCGImagePropertyExifDateTimeOriginal)
        ?: DictString(exif, kCGImagePropertyExifDateTimeDigitized)
        ?: DictString(tiff, kCGImagePropertyTIFFDateTime);
    meta.date = DateFromEXIFString(dateString);
    meta.artist = DictString(tiff, kCGImagePropertyTIFFArtist)
        ?: DictString(exif, kCGImagePropertyExifCameraOwnerName)
        ?: DictString(iptc, kCGImagePropertyIPTCByline);
    meta.copyright = DictString(tiff, kCGImagePropertyTIFFCopyright)
        ?: DictString(iptc, kCGImagePropertyIPTCCopyrightNotice);
    meta.make = DictString(tiff, kCGImagePropertyTIFFMake);
    meta.model = DictString(tiff, kCGImagePropertyTIFFModel);
    meta.lens = DictString(exif, kCGImagePropertyExifLensModel)
        ?: DictString(aux, kCGImagePropertyExifAuxLensModel);
    meta.bodySerial = DictString(exif, kCGImagePropertyExifBodySerialNumber);
    meta.lensSerial = DictString(exif, kCGImagePropertyExifLensSerialNumber)
        ?: DictString(aux, kCGImagePropertyExifAuxLensSerialNumber);
    meta.uniqueID = DictString(exif, kCGImagePropertyExifImageUniqueID);
    return meta;
}

// QuickTime/MP4 的 mvhd 创建时间（1904 纪元）
static NSDate *MovieCaptureDate(NSURL *url) {
    NSFileHandle *fh = [NSFileHandle fileHandleForReadingFromURL:url error:NULL];
    if (!fh) return nil;
    NSData *data = [fh readDataOfLength:4 * 1024 * 1024];
    [fh closeFile];
    if (data.length < 32) return nil;

    NSData *needle = [@"mvhd" dataUsingEncoding:NSASCIIStringEncoding];
    NSRange search = NSMakeRange(0, data.length);
    NSRange found = [data rangeOfData:needle options:0 range:search];
    if (found.location == NSNotFound) return nil;

    const uint8_t *b = data.bytes;
    NSUInteger p = found.location + 4;
    if (p + 8 > data.length) return nil;
    uint64_t seconds = 0;
    if (b[p] == 1) {
        if (p + 12 > data.length) return nil;
        for (int i = 0; i < 8; i++) seconds = (seconds << 8) | b[p + 4 + i];
    } else {
        for (int i = 0; i < 4; i++) seconds = (seconds << 8) | b[p + 4 + i];
    }
    if (seconds == 0) return nil;
    // 1904-01-01 与 1970-01-01 相差 2082844800 秒
    return [NSDate dateWithTimeIntervalSince1970:(double)seconds - 2082844800.0];
}

static NSDate *FileCreationDate(NSURL *url) {
    id value = nil;
    if ([url getResourceValue:&value forKey:NSURLCreationDateKey error:NULL] &&
        [value isKindOfClass:[NSDate class]]) {
        NSDate *d = value;
        if (d.timeIntervalSince1970 > 0) return d;
    }
    return nil;
}

static PhotoMetadata *MetadataForURL(NSURL *url) {
    NSString *ext = url.pathExtension.lowercaseString;
    PhotoMetadata *meta = nil;
    if ([PhotoExtensions() containsObject:ext]) {
        meta = PhotoMetadataForURL(url);
    }
    if (!meta) meta = [PhotoMetadata new];

    NSDate *date = meta.date;
    CaptureSource source = CaptureSourceEXIF;
    if (!date && [MovieExtensions() containsObject:ext]) {
        date = MovieCaptureDate(url);
    }
    if (!date) {
        date = FileCreationDate(url);
        source = CaptureSourceFileSystem;
    }
    meta.date = date;
    meta.dateSource = source;
    return meta;
}

static void CountCategoryForURL(NSURL *url, NSMutableArray<NSNumber *> *counts) {
    NSInteger category = CategoryForExtension(url.pathExtension);
    if (category < 0) return;
    counts[category] = @(counts[category].integerValue + 1);
}

static NSArray<NSNumber *> *CountFileCategories(NSArray<NSURL *> *inputs) {
    NSMutableArray<NSNumber *> *counts = [@[ @0, @0, @0, @0 ] mutableCopy];
    NSFileManager *fm = [NSFileManager defaultManager];

    for (NSURL *input in inputs) {
        BOOL isDir = NO;
        if (![fm fileExistsAtPath:input.path isDirectory:&isDir]) continue;
        if (!isDir) {
            CountCategoryForURL(input, counts);
            continue;
        }
        NSDirectoryEnumerator *e =
            [fm enumeratorAtURL:input
     includingPropertiesForKeys:@[ NSURLIsRegularFileKey ]
                        options:NSDirectoryEnumerationSkipsHiddenFiles |
                                NSDirectoryEnumerationSkipsPackageDescendants
                   errorHandler:^BOOL(NSURL *url, NSError *error) { return YES; }];
        for (NSURL *file in e) {
            NSNumber *regular = nil;
            [file getResourceValue:&regular forKey:NSURLIsRegularFileKey error:NULL];
            if (!regular.boolValue) continue;
            if ([file.lastPathComponent hasPrefix:@"._"]) continue;
            CountCategoryForURL(file, counts);
        }
    }
    return counts;
}

static NSArray<NSURL *> *CollectPreviewURLs(NSArray<NSURL *> *inputs) {
    NSMutableArray<NSURL *> *result = [NSMutableArray array];
    NSSet *preview = PreviewExtensions();
    if (!preview.count) return result;
    NSFileManager *fm = [NSFileManager defaultManager];

    for (NSURL *input in inputs) {
        BOOL isDir = NO;
        if (![fm fileExistsAtPath:input.path isDirectory:&isDir]) continue;
        if (!isDir) {
            NSString *ext = input.pathExtension.lowercaseString;
            if ([preview containsObject:ext] && !IsMediaURL(input)) [result addObject:input];
            continue;
        }
        NSDirectoryEnumerator *enumerator =
            [fm enumeratorAtURL:input includingPropertiesForKeys:nil options:0 errorHandler:nil];
        for (NSURL *url in enumerator) {
            NSString *ext = url.pathExtension.lowercaseString;
            if ([preview containsObject:ext] && !IsMediaURL(url)) [result addObject:url];
        }
    }
    return result;
}

static NSArray<NSURL *> *CollectMediaURLs(NSArray<NSURL *> *inputs) {
    NSMutableArray<NSURL *> *out = [NSMutableArray array];
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSURL *input in inputs) {
        BOOL isDir = NO;
        if (![fm fileExistsAtPath:input.path isDirectory:&isDir]) continue;
        if (!isDir) {
            if (IsMediaURL(input)) [out addObject:input];
            continue;
        }
        NSDirectoryEnumerator *e =
            [fm enumeratorAtURL:input
     includingPropertiesForKeys:@[ NSURLIsRegularFileKey ]
                        options:NSDirectoryEnumerationSkipsHiddenFiles |
                                NSDirectoryEnumerationSkipsPackageDescendants
                   errorHandler:^BOOL(NSURL *url, NSError *error) { return YES; }];
        for (NSURL *file in e) {
            NSNumber *regular = nil;
            [file getResourceValue:&regular forKey:NSURLIsRegularFileKey error:NULL];
            if (!regular.boolValue) continue;
            if ([file.lastPathComponent hasPrefix:@"._"]) continue;
            if (IsMediaURL(file)) [out addObject:file];
        }
    }
    [out sortUsingComparator:^NSComparisonResult(NSURL *a, NSURL *b) {
        return [a.path localizedStandardCompare:b.path];
    }];
    return out;
}

@class MediaItem;

static BOOL ValueMatchesKeyword(NSString *value, NSString *keyword) {
    if (!value.length || !keyword.length) return NO;
    NSString *v = [value lowercaseString];
    NSString *k = [keyword lowercaseString];
    if ([v isEqualToString:k]) return YES;
    return [v containsString:k];
}

static NSArray<NSArray *> *TopValues(NSArray<MediaItem *> *items,
                                     NSString *(^extract)(MediaItem *),
                                     NSInteger limit) {
    NSMutableDictionary<NSString *, NSNumber *> *counts = [NSMutableDictionary dictionary];
    for (MediaItem *item in items) {
        NSString *value = extract(item);
        if (!value.length) continue;
        counts[value] = @(counts[value].integerValue + 1);
    }
    NSArray *sorted = [counts.allKeys sortedArrayUsingComparator:^NSComparisonResult(NSString *a, NSString *b) {
        NSInteger ca = counts[a].integerValue;
        NSInteger cb = counts[b].integerValue;
        if (ca != cb) return ca > cb ? NSOrderedAscending : NSOrderedDescending;
        return [a localizedStandardCompare:b];
    }];
    NSMutableArray *out = [NSMutableArray array];
    for (NSString *key in sorted) {
        [out addObject:@[ key, counts[key] ]];
        if ((NSInteger)out.count >= limit) break;
    }
    return out;
}

static NSString *JoinedTopValues(NSArray<NSArray *> *values) {
    NSMutableArray *parts = [NSMutableArray array];
    for (NSArray *pair in values) {
        if ([pair.firstObject length]) [parts addObject:pair.firstObject];
    }
    return [parts componentsJoinedByString:@"、"];
}


#pragma mark - 归档结构

@interface ArchivePlan : NSObject
@property (nonatomic) NSURL *rootURL;
@property (nonatomic) NSDate *date;
@property (nonatomic) NSString *event;
@property (nonatomic) BOOL flatMode;               // YES = 并列命名
@property (nonatomic) NSString *manualSignature;      // 手动署名（最外层）
@property (nonatomic) NSString *autoSignature;          // 自动署名（单人模式用于最外层）
@property (nonatomic) BOOL autoSignEnabled;             // 是否启用自动署名
@property (nonatomic) BOOL multiPerson;                 // 多人模式
@property (nonatomic) NSArray<NSString *> *subfolders;   // 额外文件夹（筛选/收集…）
@property (nonatomic) BOOL includesVideo;                    // 本批是否包含视频
@property (nonatomic) NSArray<NSString *> *photoAuthors;    // 原始照片下的人名
@property (nonatomic) NSArray<NSString *> *videoAuthors;    // 原始视频下的人名
@property (nonatomic) NSString *sourceTag;                   // 来源标签，如 拷卡
@property (nonatomic) BOOL verifyCopies;                     // 复制后校验
@property (nonatomic) NSInteger verifyKind;                  // 0=xxHash64 1=MD5
- (NSString *)baseName;
- (NSURL *)eventDirectoryURL;
- (NSURL *)directoryURLForFolderName:(NSString *)name;
- (NSURL *)originalPhotoDirectoryURL;
- (NSURL *)originalVideoDirectoryURL;
- (NSArray<NSString *> *)originalFolderNames;
- (NSArray<NSString *> *)authorFolderNames;
- (NSArray<NSString *> *)videoAuthorNames;
- (NSArray<NSURL *> *)leafDirectoryURLs;
- (NSURL *)primaryDirectoryURL;
- (NSString *)treeText;
@end

@implementation ArchivePlan

- (NSString *)eventSignature {
    NSString *manual = SanitizeComponent(self.manualSignature ?: @"");
    if (manual.length) return manual;   // 手动署名优先
    if (!self.multiPerson && self.autoSignEnabled) {
        NSString *autoSign = SanitizeComponent(self.autoSignature ?: @"");
        return autoSign.length ? autoSign : nil;
    }
    return nil;
}

- (NSString *)baseName {
    NSString *base = FolderBaseName(self.date ?: [NSDate date], self.event);
    NSString *sign = [self eventSignature];
    if (sign.length) base = [base stringByAppendingFormat:@"_%@", sign];
    return base;
}

- (NSArray<NSString *> *)effectiveSubfolders {
    return self.subfolders ?: SubfolderPresets();
}

- (NSURL *)eventDirectoryURL {
    if (self.flatMode) return nil;
    return [self.rootURL URLByAppendingPathComponent:[self baseName] isDirectory:YES];
}

- (NSURL *)directoryURLForFolderName:(NSString *)name {
    if (self.flatMode) {
        NSString *folder = [[self baseName] stringByAppendingString:name];
        return [self.rootURL URLByAppendingPathComponent:folder isDirectory:YES];
    }
    return [[self eventDirectoryURL] URLByAppendingPathComponent:name isDirectory:YES];
}

- (NSURL *)originalPhotoDirectoryURL {
    return [self directoryURLForFolderName:kOriginalPhotoName];
}

- (NSURL *)originalVideoDirectoryURL {
    return [self directoryURLForFolderName:kOriginalVideoName];
}

- (NSArray<NSString *> *)originalFolderNames {
    NSMutableArray *names = [NSMutableArray arrayWithObject:kOriginalPhotoName];
    if (self.includesVideo) [names addObject:kOriginalVideoName];
    return names;
}

- (NSString *)cleanSourceTag {
    return SanitizeComponent(self.sourceTag ?: @"");
}

- (NSString *)taggedFolderName:(NSString *)name {
    NSString *tag = [self cleanSourceTag];
    return tag.length ? [name stringByAppendingFormat:@"_%@", tag] : name;
}

- (NSArray<NSString *> *)sanitizedAuthorList:(NSArray<NSString *> *)list {
    NSMutableArray *names = [NSMutableArray array];
    for (NSString *author in list) {
        NSString *clean = SanitizeComponent(author);
        if (!clean.length) continue;
        clean = [self taggedFolderName:clean];
        if (![names containsObject:clean]) [names addObject:clean];
    }
    return names;
}

- (NSArray<NSString *> *)authorFolderNames {
    if (!self.multiPerson) return @[];
    return [self sanitizedAuthorList:self.photoAuthors];
}

- (NSArray<NSString *> *)videoAuthorNames {
    if (!self.multiPerson || !self.includesVideo) return @[];
    return [self sanitizedAuthorList:self.videoAuthors];
}

- (NSArray<NSURL *> *)leafDirectoryURLs {
    NSMutableArray *urls = [NSMutableArray array];
    for (NSString *name in [self originalFolderNames]) {
        [urls addObject:[self directoryURLForFolderName:name]];
    }
    NSArray *photoAuthors = [self authorFolderNames];
    if (photoAuthors.count) {
        NSURL *photoDir = [self originalPhotoDirectoryURL];
        for (NSString *author in photoAuthors) {
            [urls addObject:[photoDir URLByAppendingPathComponent:author isDirectory:YES]];
        }
    }
    NSArray *videoAuthors = [self videoAuthorNames];
    if (videoAuthors.count) {
        NSURL *videoDir = [self originalVideoDirectoryURL];
        for (NSString *author in videoAuthors) {
            [urls addObject:[videoDir URLByAppendingPathComponent:author isDirectory:YES]];
        }
    }
    for (NSString *name in [self effectiveSubfolders]) {
        [urls addObject:[self directoryURLForFolderName:name]];
    }
    return urls;
}

- (NSURL *)primaryDirectoryURL {
    return [self originalPhotoDirectoryURL];
}

- (NSString *)treeText {
    NSMutableString *s = [NSMutableString string];
    NSString *base = [self baseName];
    NSMutableArray *names = [NSMutableArray arrayWithArray:[self originalFolderNames]];
    [names addObjectsFromArray:[self effectiveSubfolders]];

    [s appendFormat:@"%@/\n", AbbreviatePath(self.rootURL.path)];
    if (!self.flatMode) {
        [s appendFormat:@"└── %@/\n", base];
        for (NSUInteger i = 0; i < names.count; i++) {
            BOOL last = (i == names.count - 1);
            [s appendFormat:@"    %@%@/\n", last ? @"└── " : @"├── ", names[i]];
        }
    } else {
        for (NSUInteger i = 0; i < names.count; i++) {
            BOOL last = (i == names.count - 1);
            [s appendFormat:@"%@%@%@/\n", last ? @"└── " : @"├── ", base, names[i]];
        }
    }
    return s;
}

@end

static NSString *EventModeKey(NSString *eventPath) {
    return [@"eventMode." stringByAppendingString:eventPath ?: @""];
}

/// 创建目录，返回新建的目录路径；已存在的不会重复创建。
static NSArray<NSURL *> *CreateDirectories(ArchivePlan *plan, NSError **error) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray *created = [NSMutableArray array];
    NSMutableArray *targets = [NSMutableArray array];

    if (!plan.flatMode) {
        NSURL *eventURL = [plan.rootURL URLByAppendingPathComponent:[plan baseName] isDirectory:YES];
        BOOL eventExisted = [fm fileExistsAtPath:eventURL.path];
        [targets addObject:eventURL];
        if (!eventExisted) {
            [[NSUserDefaults standardUserDefaults]
                setObject:(plan.multiPerson ? @"multi" : @"single")
                   forKey:EventModeKey(eventURL.path)];
        }
    }
    [targets addObjectsFromArray:[plan leafDirectoryURLs]];

    for (NSURL *url in targets) {
        BOOL isDir = NO;
        BOOL exists = [fm fileExistsAtPath:url.path isDirectory:&isDir];
        if (exists && isDir) continue;
        if (exists && !isDir) {
            if (error) {
                *error = [NSError errorWithDomain:@"AutoArchive"
                                             code:1
                                         userInfo:@{NSLocalizedDescriptionKey:
                                                        [NSString stringWithFormat:@"“%@”已存在且不是文件夹。", url.lastPathComponent]}];
            }
            return created;
        }
        NSError *err = nil;
        if (![fm createDirectoryAtURL:url withIntermediateDirectories:YES attributes:nil error:&err]) {
            if (error) *error = err;
            return created;
        }
        [created addObject:url];
    }
    return created;
}

/// 重命名文件夹：目标存在时不覆盖，返回 NO 并给出原因。
static BOOL SafeRenameDirectory(NSURL *source, NSURL *destination, NSString **errorMessage) {
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL sourceIsDir = NO;
    if (![fm fileExistsAtPath:source.path isDirectory:&sourceIsDir] || !sourceIsDir) {
        return YES;  // 源不存在，无需重命名
    }
    if ([fm fileExistsAtPath:destination.path]) {
        if (errorMessage) *errorMessage = @"同名文件夹已存在";
        return NO;
    }
    NSError *error = nil;
    if (![fm moveItemAtURL:source toURL:destination error:&error]) {
        if (errorMessage) *errorMessage = error.localizedDescription ?: @"重命名失败";
        return NO;
    }
    return YES;
}

#pragma mark - 导入结果

@interface ImportResult : NSObject
@property (nonatomic) NSInteger copied;
@property (nonatomic) NSInteger moved;
@property (nonatomic) NSInteger skipped;
@property (nonatomic) NSInteger renamed;
@property (nonatomic) NSInteger failed;
@property (nonatomic) NSInteger verified;
@property (nonatomic) NSInteger verifyFailed;
@property (nonatomic) NSMutableArray<NSString *> *errors;
@end

@implementation ImportResult
- (instancetype)init {
    if ((self = [super init])) _errors = [NSMutableArray array];
    return self;
}
@end

/// 解析目标路径：同名同内容视为重复（跳过），同名不同内容则加 _2、_3 后缀。
/// 已经以 _N 后缀归档过的文件也能被识别为重复，重复导入不会产生副本。
static NSURL *ResolveDestination(NSURL *dir, NSURL *src, NSString *filename,
                                 BOOL *duplicate, BOOL *renamed) {
    NSFileManager *fm = [NSFileManager defaultManager];
    if (duplicate) *duplicate = NO;
    if (renamed) *renamed = NO;

    NSURL *candidate = [dir URLByAppendingPathComponent:filename];
    if (![fm fileExistsAtPath:candidate.path]) return candidate;
    if ([fm contentsEqualAtPath:src.path andPath:candidate.path]) {
        if (duplicate) *duplicate = YES;
        return candidate;
    }

    NSString *base = filename.stringByDeletingPathExtension;
    NSString *ext = filename.pathExtension;
    for (int i = 2; i < 10000; i++) {
        NSString *variant = ext.length ? [NSString stringWithFormat:@"%@_%d.%@", base, i, ext]
                                       : [NSString stringWithFormat:@"%@_%d", base, i];
        candidate = [dir URLByAppendingPathComponent:variant];
        if (![fm fileExistsAtPath:candidate.path]) {
            if (renamed) *renamed = YES;
            return candidate;
        }
        if ([fm contentsEqualAtPath:src.path andPath:candidate.path]) {
            if (duplicate) *duplicate = YES;
            return candidate;
        }
    }
    return candidate;
}

static void ImportItems(ArchivePlan *plan,
                        NSArray<NSURL *> *items,
                        NSDictionary<NSString *, NSString *> *authorByPath,
                        NSSet<NSString *> *videoLikePaths,
                        BOOL move,
                        void (^progress)(NSInteger done, NSInteger total),
                        ImportResult *result) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSURL *photoTarget = [plan originalPhotoDirectoryURL];
    NSURL *videoTarget = [plan originalVideoDirectoryURL];
    NSInteger total = (NSInteger)items.count;
    NSInteger done = 0;

    for (NSURL *src in items) {
        @autoreleasepool {
            NSString *name = src.lastPathComponent;
            NSString *ext = src.pathExtension.lowercaseString;
            BOOL isVideo = [videoLikePaths containsObject:src.path] ||
                           [MovieExtensions() containsObject:ext] ||
                           [AudioExtensions() containsObject:ext];
            NSURL *target = isVideo ? (videoTarget ?: photoTarget) : photoTarget;

            NSString *person = nil;
            if (plan.multiPerson) {
                person = SanitizeComponent(authorByPath[src.path] ?: @"");
                if (!person.length) person = kUnknownAuthorName;
            }

            NSString *folderName = nil;
            if (person.length) {
                folderName = [plan taggedFolderName:person];
            }
            if (folderName.length) {
                target = [target URLByAppendingPathComponent:folderName isDirectory:YES];
                [fm createDirectoryAtURL:target withIntermediateDirectories:YES attributes:nil error:NULL];
            }

            BOOL duplicate = NO, renamed = NO;
            NSURL *dest = ResolveDestination(target, src, name, &duplicate, &renamed);
            if (duplicate) {
                result.skipped++;
                done++;
                if (progress) progress(done, total);
                continue;
            }
            if (renamed) result.renamed++;

            NSError *err = nil;
            BOOL ok = YES;
            NSString *failure = nil;
            BOOL verify = plan.verifyCopies;

            if (move && !verify) {
                ok = [fm moveItemAtURL:src toURL:dest error:&err];
                if (ok) {
                    result.moved++;
                } else {
                    failure = err.localizedDescription ?: @"未知错误";
                }
            } else {
                ok = [fm copyItemAtURL:src toURL:dest error:&err];
                if (!ok) {
                    failure = err.localizedDescription ?: @"未知错误";
                } else if (verify) {
                    NSString *algorithm = (plan.verifyKind == 1) ? @"MD5" : @"xxHash64";
                    NSString *sourceHash = HashFileAtURL(src, plan.verifyKind);
                    NSString *destHash = HashFileAtURL(dest, plan.verifyKind);
                    if (!sourceHash.length || !destHash.length ||
                        ![sourceHash isEqualToString:destHash]) {
                        [fm removeItemAtURL:dest error:NULL];
                        result.verifyFailed++;
                        failure = [NSString stringWithFormat:@"%@ 校验不通过", algorithm];
                        ok = NO;
                    } else {
                        result.verified++;
                    }
                }

                if (ok && move) {
                    NSError *removeError = nil;
                    if ([fm removeItemAtURL:src error:&removeError]) {
                        result.moved++;
                    } else {
                        failure = [NSString stringWithFormat:@"已校验，但删除源文件失败：%@",
                                   removeError.localizedDescription ?: @"未知错误"];
                        ok = NO;
                    }
                } else if (ok) {
                    result.copied++;
                }
            }

            if (!ok) {
                result.failed++;
                [result.errors addObject:
                    [NSString stringWithFormat:@"%@：%@", name, failure ?: @"未知错误"]];
            }
        }
        done++;
        if (progress) progress(done, total);
    }
}

#pragma mark - 媒体条目

@interface MediaItem : NSObject
@property (nonatomic) NSURL *url;
@property (nonatomic) PhotoMetadata *meta;
@property (nonatomic) BOOL previewFile;
@end
@implementation MediaItem
@end


@interface FlippedStackView : NSStackView
@end

@interface StatusChipView : NSView
@property (nonatomic) NSTextField *label;
- (void)setStatusText:(NSString *)text color:(NSColor *)color tooltip:(NSString *)tooltip;
@end

@implementation StatusChipView

- (instancetype)initWithFrame:(NSRect)frameRect {
    if ((self = [super initWithFrame:frameRect])) {
        self.wantsLayer = YES;
        self.layer.cornerRadius = 6;
        self.layer.masksToBounds = YES;

        _label = [[NSTextField alloc] init];
        _label.editable = NO;
        _label.selectable = NO;
        _label.bezeled = NO;
        _label.drawsBackground = NO;
        _label.alignment = NSTextAlignmentCenter;
        _label.font = [NSFont systemFontOfSize:11.5 weight:NSFontWeightSemibold];
        _label.textColor = [NSColor whiteColor];
        _label.lineBreakMode = NSLineBreakByTruncatingTail;
        _label.translatesAutoresizingMaskIntoConstraints = NO;
        [self addSubview:_label];
        [NSLayoutConstraint activateConstraints:@[
            [_label.centerXAnchor constraintEqualToAnchor:self.centerXAnchor],
            [_label.centerYAnchor constraintEqualToAnchor:self.centerYAnchor],
            [_label.leadingAnchor constraintGreaterThanOrEqualToAnchor:self.leadingAnchor constant:6],
            [_label.trailingAnchor constraintLessThanOrEqualToAnchor:self.trailingAnchor constant:-6],
        ]];
    }
    return self;
}

- (void)setStatusText:(NSString *)text color:(NSColor *)color tooltip:(NSString *)tooltip {
    self.label.stringValue = text ?: @"";
    self.toolTip = tooltip;
    self.layer.backgroundColor = color.CGColor;
}

@end

@interface FolderTrashButton : NSButton
@property (nonatomic) NSURL *folderURL;
@property (nonatomic) NSString *folderName;
@property (nonatomic) BOOL isExtraFolder;
@end

@implementation FolderTrashButton
@end

@implementation FlippedStackView
- (BOOL)isFlipped { return YES; }
@end

#pragma mark - 拖拽接收

@interface DropView : NSView
@property (nonatomic, copy) void (^onDrop)(NSArray<NSURL *> *urls);
@end

@implementation DropView

- (instancetype)initWithFrame:(NSRect)frameRect {
    if ((self = [super initWithFrame:frameRect])) {
        [self registerForDraggedTypes:@[ NSPasteboardTypeFileURL ]];
    }
    return self;
}

- (NSArray<NSURL *> *)fileURLsFrom:(id<NSDraggingInfo>)info {
    NSDictionary *options = @{ NSPasteboardURLReadingFileURLsOnlyKey : @YES };
    NSArray *urls = [info.draggingPasteboard readObjectsForClasses:@[ [NSURL class] ]
                                                           options:options];
    return urls ?: @[];
}

- (void)setHighlighted:(BOOL)highlighted {
    self.layer.borderWidth = highlighted ? 2 : 0;
    self.layer.borderColor = [NSColor controlAccentColor].CGColor;
    self.layer.cornerRadius = 10;
}

- (NSDragOperation)draggingEntered:(id<NSDraggingInfo>)sender {
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSURL *url in [self fileURLsFrom:sender]) {
        BOOL isDir = NO;
        if ([fm fileExistsAtPath:url.path isDirectory:&isDir] && (isDir || IsMediaURL(url))) {
            [self setHighlighted:YES];
            return NSDragOperationCopy;
        }
    }
    return NSDragOperationNone;
}

- (void)draggingExited:(id<NSDraggingInfo>)sender {
    [self setHighlighted:NO];
}

- (BOOL)performDragOperation:(id<NSDraggingInfo>)sender {
    [self setHighlighted:NO];
    NSArray<NSURL *> *urls = [self fileURLsFrom:sender];
    if (urls.count && self.onDrop) self.onDrop(urls);
    return urls.count > 0;
}

@end

#pragma mark - 界面

@interface AppDelegate : NSObject <NSApplicationDelegate, NSWindowDelegate, NSTextFieldDelegate, NSTokenFieldDelegate>
@property (nonatomic) NSWindow *window;
@property (nonatomic) NSTextField *rootField;
@property (nonatomic) NSTextField *eventField;
@property (nonatomic) NSTokenField *subsTokenField;
@property (nonatomic) NSButton *subsMenuButton;
@property (nonatomic) NSArray<NSDictionary *> *subfolderRecents;
@property (nonatomic) NSStackView *treeStack;
@property (nonatomic) NSScrollView *treeScrollView;
@property (nonatomic) NSTextField *pendingNewField;
@property (nonatomic) BOOL rebuildingTree;
@property (nonatomic) BOOL committingTreeField;
@property (nonatomic) NSTextField *statusLabel;
@property (nonatomic) NSTextField *sourceLabel;
@property (nonatomic) NSTextField *modeHintLabel;
@property (nonatomic) NSTextField *signField;
@property (nonatomic) NSStackView *metaGrid;
@property (nonatomic) NSTextField *autoSignNoteLabel;
@property (nonatomic) NSStackView *categoryRow;
@property (nonatomic) NSButton *signCheck;
@property (nonatomic) NSButton *rulesButton;
@property (nonatomic) NSWindow *rulesWindow;
@property (nonatomic) NSStackView *rulesStackView;
@property (nonatomic) NSArray<NSDictionary *> *signRules;
@property (nonatomic) NSButton *autoSignCheck;
@property (nonatomic) StatusChipView *autoSignStatusView;
@property (nonatomic) NSArray<NSString *> *detectedRawAuthors;
@property (nonatomic) NSMutableSet<NSString *> *conflictShownKeys;
@property (nonatomic) NSMutableSet<NSString *> *promptedUnknownAuthors;
@property (nonatomic) NSWindow *unknownWindow;
@property (nonatomic) NSStackView *unknownRowsStack;
@property (nonatomic) NSArray<NSDictionary *> *unknownEntries;
@property (nonatomic) NSArray<NSTextField *> *unknownFields;
@property (nonatomic) NSArray<NSButton *> *unknownSaveChecks;
@property (nonatomic) NSMutableDictionary<NSString *, NSString *> *batchSignatureMappings;
@property (nonatomic) NSMutableDictionary<NSString *, NSString *> *batchFolderPersonMappings;
@property (nonatomic) NSButton *unknownFolderInferenceCheck;
@property (nonatomic) NSArray<NSDictionary *> *pendingInferenceAssignments;
@property (nonatomic) NSDate *dateBeforeScan;
@property (nonatomic) NSStackView *sourceTagRow;
@property (nonatomic) NSSegmentedControl *personModeControl;
@property (nonatomic) NSTextField *personModeHintLabel;
@property (nonatomic) BOOL personModeLocked;
@property (nonatomic) NSString *autoSignature;
@property (nonatomic) BOOL multiPerson;
@property (nonatomic) BOOL batchHasVideo;
@property (nonatomic) NSArray<NSString *> *detectedAuthors;
@property (nonatomic) NSArray<NSString *> *detectedPhotoAuthors;
@property (nonatomic) NSArray<NSString *> *detectedVideoAuthors;
@property (nonatomic) NSDatePicker *datePicker;
@property (nonatomic) NSButton *autoDateCheck;
@property (nonatomic) NSButton *todayButton;
@property (nonatomic) NSButton *sourceTagCheck;
@property (nonatomic) NSComboBox *sourceTagCombo;
@property (nonatomic) NSButton *verifyCheck;
@property (nonatomic) NSPopUpButton *verifyKindPopup;
@property (nonatomic) StatusChipView *verifyResultChip;
@property (nonatomic) NSArray<NSTextField *> *categoryLabels;
@property (nonatomic) NSWindow *settingsWindow;
@property (nonatomic) NSTokenField *imageExtField;
@property (nonatomic) NSTokenField *rawExtField;
@property (nonatomic) NSTokenField *videoExtField;
@property (nonatomic) NSTokenField *audioExtField;
@property (nonatomic) NSTokenField *previewExtField;
@property (nonatomic) NSTokenField *tagPresetsTokenField;
@property (nonatomic) NSTokenField *subfolderPresetsTokenField;
@property (nonatomic) NSWindow *aboutWindow;
@property (nonatomic) NSSegmentedControl *aboutSegment;
@property (nonatomic) NSTextView *aboutTextView;
@property (nonatomic) NSSegmentedControl *modeControl;

@property (nonatomic) NSButton *createButton;
@property (nonatomic) NSButton *importButton;
@property (nonatomic) NSButton *revealButton;
@property (nonatomic) NSButton *folderButton;
@property (nonatomic) NSButton *filesButton;
@property (nonatomic) NSButton *radioCopy;
@property (nonatomic) NSButton *moveRadio;
@property (nonatomic) NSProgressIndicator *progress;
@property (nonatomic) NSProgressIndicator *spinner;
@property (nonatomic) NSArray<MediaItem *> *items;
@property (nonatomic) NSArray<NSURL *> *pendingPreviewURLs;
@property (nonatomic) NSArray<NSURL *> *sourceURLs;
@property (nonatomic) BOOL busy;
@end

@implementation AppDelegate

#pragma mark 生命周期

- (void)applicationDidFinishLaunching:(NSNotification *)note {
    // 界面配色按浅色设计，固定外观避免深色模式下自定义颜色错位
    [NSApp setAppearance:[NSAppearance appearanceNamed:NSAppearanceNameAqua]];
    [self buildMenu];
    [self buildWindow];
    [self buildInterface];
    [self restoreSettings];
    [self refreshPreview];
    [self.window makeKeyAndOrderFront:nil];
    [self.window makeFirstResponder:self.eventField];
    [NSApp activateIgnoringOtherApps:YES];

    NSString *scan = [NSString stringWithUTF8String:getenv("DSH_SCAN") ?: ""];
    if (scan.length) {
        [self loadSources:@[ [NSURL fileURLWithPath:scan] ] description:scan.lastPathComponent];
    }

    if (getenv("DSH_RULES")) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.35 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [self showRules:nil];
        });
    }

    if (getenv("DSH_ABOUT")) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.35 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [self showAbout:nil];
            const char *tab = getenv("DSH_ABOUT_TAB");
            if (tab) {
                self.aboutSegment.selectedSegment = atoi(tab);
                [self updateAboutContent];
            }
        });
    }

    if (getenv("DSH_SETTINGS")) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.35 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [self showSettings:nil];
        });
    }

    NSString *shot = [NSString stringWithUTF8String:getenv("DSH_SNAPSHOT") ?: ""];
    if (shot.length) {
        [self applyDemoStateIfNeeded];
        NSString *rootOverride = [NSString stringWithUTF8String:getenv("DSH_ROOT") ?: ""];
        if (rootOverride.length) {
            self.rootField.stringValue = rootOverride;
            [self refreshPreview];
        }
        double delay = (scan.length || getenv("DSH_RULES") || getenv("DSH_SETTINGS") ||
                        getenv("DSH_ABOUT")) ? 1.4 : 0.5;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [self writeSnapshotTo:shot];
            if (getenv("DSH_SNAPSHOT")) exit(0);
            [NSApp terminate:nil];
        });
    }
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender {
    return YES;
}

- (void)applicationWillTerminate:(NSNotification *)notification {
    [self saveSettings];
}

- (void)applyDemoStateIfNeeded {
    if (!getenv("DSH_DEMO")) return;
    [self.window makeFirstResponder:nil];
    self.rootField.stringValue = @"~/Pictures/自动归档";
    self.eventField.stringValue = @"毕业典礼";
    self.signCheck.state = NSControlStateValueOn;
    self.signField.enabled = YES;
    self.signField.stringValue = @"张三";
    self.sourceTagCheck.state = NSControlStateValueOn;
    self.sourceTagCombo.enabled = YES;
    self.sourceTagCombo.stringValue = @"拷卡";
    self.verifyCheck.state = NSControlStateValueOn;
    self.verifyKindPopup.enabled = YES;
    NSDateComponents *c = [NSDateComponents new];
    c.year = 2026; c.month = 10; c.day = 19;
    NSDate *d = [[NSCalendar currentCalendar] dateFromComponents:c];
    if (d) self.datePicker.dateValue = d;
    self.statusLabel.stringValue = @"共 128 个文件 · 拍摄时间 2026-10-19 09:12 ~ 18:40 · 2 个无拍摄时间（按文件时间）";
    [self refreshPreview];
}

- (void)writeSnapshotTo:(NSString *)path {
    NSWindow *target = self.window;
    if (getenv("DSH_RULES") && self.rulesWindow.isVisible) target = self.rulesWindow;
    if (getenv("DSH_SETTINGS") && self.settingsWindow.isVisible) target = self.settingsWindow;
    if (getenv("DSH_ABOUT") && self.aboutWindow.isVisible) target = self.aboutWindow;
    if (self.unknownWindow.isVisible) target = self.unknownWindow;
    if (getenv("DSH_AUTO_SAVE_UNKNOWN") && self.window.attachedSheet) {
        target = self.window.attachedSheet;
    }
    [NSApp activateIgnoringOtherApps:YES];
    [target makeKeyAndOrderFront:nil];
    [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.2]];
    NSView *view = target.contentView;
    NSRect rect = view.bounds;
    NSBitmapImageRep *rep = [view bitmapImageRepForCachingDisplayInRect:rect];
    [view cacheDisplayInRect:rect toBitmapImageRep:rep];
    NSData *png = [rep representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
    [png writeToFile:path atomically:YES];
}

#pragma mark 菜单

- (void)buildMenu {
    NSMenu *mainMenu = [NSMenu new];

    NSMenuItem *appItem = [NSMenuItem new];
    [mainMenu addItem:appItem];
    NSMenu *appMenu = [NSMenu new];
    NSMenuItem *aboutItem = [appMenu addItemWithTitle:@"关于 自动归档"
                                               action:@selector(showAbout:)
                                        keyEquivalent:@""];
    aboutItem.target = self;
    [appMenu addItem:[NSMenuItem separatorItem]];
    [appMenu addItemWithTitle:@"隐藏 自动归档" action:@selector(hide:) keyEquivalent:@"h"];
    [appMenu addItemWithTitle:@"隐藏其他" action:@selector(hideOtherApplications:) keyEquivalent:@"h"];
    [appMenu addItem:[NSMenuItem separatorItem]];
    NSMenuItem *settingsItem = [appMenu addItemWithTitle:@"设置…"
                                                  action:@selector(showSettings:)
                                           keyEquivalent:@","];
    settingsItem.target = self;
    [appMenu addItem:[NSMenuItem separatorItem]];
    [appMenu addItemWithTitle:@"退出 自动归档" action:@selector(terminate:) keyEquivalent:@"q"];
    appItem.submenu = appMenu;

    NSMenuItem *editItem = [NSMenuItem new];
    [mainMenu addItem:editItem];
    NSMenu *editMenu = [[NSMenu alloc] initWithTitle:@"编辑"];
    [editMenu addItemWithTitle:@"撤销" action:@selector(undo:) keyEquivalent:@"z"];
    [editMenu addItem:[NSMenuItem separatorItem]];
    [editMenu addItemWithTitle:@"剪切" action:@selector(cut:) keyEquivalent:@"x"];
    [editMenu addItemWithTitle:@"拷贝" action:@selector(copy:) keyEquivalent:@"c"];
    [editMenu addItemWithTitle:@"粘贴" action:@selector(paste:) keyEquivalent:@"v"];
    [editMenu addItemWithTitle:@"全选" action:@selector(selectAll:) keyEquivalent:@"a"];
    editItem.submenu = editMenu;

    [NSApp setMainMenu:mainMenu];
}

#pragma mark 窗口与控件

- (NSTextField *)label:(NSString *)text font:(NSFont *)font color:(NSColor *)color {
    NSTextField *l = [NSTextField labelWithString:text];
    l.font = font;
    l.textColor = color;
    l.lineBreakMode = NSLineBreakByTruncatingTail;
    l.translatesAutoresizingMaskIntoConstraints = NO;
    return l;
}

- (NSTextField *)sectionLabel:(NSString *)text {
    NSTextField *l = [self label:text
                            font:[NSFont systemFontOfSize:11.5 weight:NSFontWeightSemibold]
                           color:[NSColor secondaryLabelColor]];
    return l;
}

- (NSButton *)button:(NSString *)title action:(SEL)action {
    NSButton *b = [NSButton buttonWithTitle:title target:self action:action];
    b.bezelStyle = NSBezelStyleRounded;
    b.controlSize = NSControlSizeRegular;
    b.translatesAutoresizingMaskIntoConstraints = NO;
    [b setContentHuggingPriority:800 forOrientation:NSLayoutConstraintOrientationHorizontal];
    [b setContentCompressionResistancePriority:800 forOrientation:NSLayoutConstraintOrientationHorizontal];
    return b;
}

- (void)buildWindow {
    NSWindow *w = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 780, 720)
                                              styleMask:(NSWindowStyleMaskTitled |
                                                         NSWindowStyleMaskClosable |
                                                         NSWindowStyleMaskMiniaturizable |
                                                         NSWindowStyleMaskResizable)
                                                backing:NSBackingStoreBuffered
                                                  defer:NO];
    w.title = kAppTitle;
    w.minSize = NSMakeSize(780, 700);
    w.delegate = self;

    DropView *dropView = [[DropView alloc] initWithFrame:NSMakeRect(0, 0, 780, 720)];
    dropView.wantsLayer = YES;
    __weak typeof(self) weakSelf = self;
    dropView.onDrop = ^(NSArray<NSURL *> *urls) {
        NSString *desc = urls.count == 1 ? urls.firstObject.lastPathComponent
                                         : [NSString stringWithFormat:@"%lu 个文件", (unsigned long)urls.count];
        [weakSelf loadSources:urls description:desc];
    };
    w.contentView = dropView;

    [w center];
    self.window = w;
}

- (NSStackView *)rowWithViews:(NSArray<NSView *> *)views {
    NSStackView *row = [NSStackView stackViewWithViews:views];
    row.orientation = NSUserInterfaceLayoutOrientationHorizontal;
    row.alignment = NSLayoutAttributeCenterY;
    row.spacing = 10;
    row.distribution = NSStackViewDistributionFill;
    row.translatesAutoresizingMaskIntoConstraints = NO;
    return row;
}

- (NSView *)gapView {
    NSView *gap = [NSView new];
    gap.translatesAutoresizingMaskIntoConstraints = NO;
    [gap setContentHuggingPriority:1 forOrientation:NSLayoutConstraintOrientationHorizontal];
    [gap setContentCompressionResistancePriority:1 forOrientation:NSLayoutConstraintOrientationHorizontal];
    return gap;
}

- (NSStackView *)formRow:(NSString *)title control:(NSView *)control extra:(NSView *)extra {
    NSTextField *l = [self label:title
                            font:[NSFont systemFontOfSize:12.5]
                           color:[NSColor secondaryLabelColor]];
    l.alignment = NSTextAlignmentRight;
    [l.widthAnchor constraintEqualToConstant:70].active = YES;
    [l setContentCompressionResistancePriority:800 forOrientation:NSLayoutConstraintOrientationHorizontal];

    NSMutableArray *views = [NSMutableArray arrayWithObjects:l, control, nil];
    if (extra) {
        if (![control isKindOfClass:[NSTextField class]]) {
            [views addObject:[self gapView]];
        }
        [views addObject:extra];
    }
    return [self rowWithViews:views];
}

- (void)buildInterface {
    NSView *content = self.window.contentView;
    content.wantsLayer = YES;

    NSStackView *root = [NSStackView new];
    root.orientation = NSUserInterfaceLayoutOrientationVertical;
    root.alignment = NSLayoutAttributeLeading;
    root.spacing = 8;
    root.translatesAutoresizingMaskIntoConstraints = NO;
    [content addSubview:root];
    [NSLayoutConstraint activateConstraints:@[
        [root.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:26],
        [root.trailingAnchor constraintEqualToAnchor:content.trailingAnchor constant:-26],
        [root.topAnchor constraintEqualToAnchor:content.topAnchor constant:16],
        [root.bottomAnchor constraintEqualToAnchor:content.bottomAnchor constant:-14],
    ]];

    [root.widthAnchor constraintGreaterThanOrEqualToConstant:728].active = YES;

    void (^addRow)(NSView *) = ^(NSView *v) {
        [root addArrangedSubview:v];
        [v.widthAnchor constraintEqualToAnchor:root.widthAnchor].active = YES;
    };

    // 标题
    NSTextField *title = [self label:kAppTitle
                                font:[NSFont systemFontOfSize:23 weight:NSFontWeightSemibold]
                               color:[NSColor labelColor]];
    NSImage *gearImage = [NSImage imageWithSystemSymbolName:@"gearshape"
                                     accessibilityDescription:@"设置"];
    gearImage = [gearImage imageWithSymbolConfiguration:
                 [NSImageSymbolConfiguration configurationWithPointSize:14 weight:NSFontWeightRegular]];
    NSButton *settingsButton = [NSButton buttonWithImage:gearImage
                                                  target:self
                                                  action:@selector(showSettings:)];
    settingsButton.bordered = NO;
    settingsButton.imagePosition = NSImageOnly;
    settingsButton.contentTintColor = [NSColor tertiaryLabelColor];
    settingsButton.toolTip = @"设置";
    settingsButton.translatesAutoresizingMaskIntoConstraints = NO;
    [settingsButton.widthAnchor constraintEqualToConstant:26].active = YES;
    [settingsButton.heightAnchor constraintEqualToConstant:26].active = YES;

    NSImage *infoImage = [NSImage imageWithSystemSymbolName:@"info.circle"
                                   accessibilityDescription:@"关于"];
    infoImage = [infoImage imageWithSymbolConfiguration:
                 [NSImageSymbolConfiguration configurationWithPointSize:14 weight:NSFontWeightRegular]];
    NSButton *aboutButton = [NSButton buttonWithImage:infoImage
                                               target:self
                                               action:@selector(showAbout:)];
    aboutButton.bordered = NO;
    aboutButton.imagePosition = NSImageOnly;
    aboutButton.contentTintColor = [NSColor tertiaryLabelColor];
    aboutButton.toolTip = @"关于 自动归档";
    aboutButton.translatesAutoresizingMaskIntoConstraints = NO;
    [aboutButton.widthAnchor constraintEqualToConstant:26].active = YES;
    [aboutButton.heightAnchor constraintEqualToConstant:26].active = YES;
    NSStackView *titleRow = [self rowWithViews:@[ title, [self gapView],
                                                  settingsButton, aboutButton ]];
    [titleRow setCustomSpacing:4 afterView:settingsButton];
    addRow(titleRow);
    [root setCustomSpacing:12 afterView:titleRow];

    // ① 归档位置
    [root addArrangedSubview:[self sectionLabel:@"归档位置"]];
    self.rootField = [NSTextField textFieldWithString:@""];
    self.rootField.translatesAutoresizingMaskIntoConstraints = NO;
    self.rootField.font = [NSFont systemFontOfSize:13];
    self.rootField.placeholderString = @"选择归档根目录";
    self.rootField.delegate = self;
    [self.rootField setContentHuggingPriority:1 forOrientation:NSLayoutConstraintOrientationHorizontal];
    NSButton *chooseRoot = [self button:@"选择…" action:@selector(chooseRootDirectory:)];
    addRow([self formRow:@"" control:self.rootField extra:chooseRoot]);
    [root setCustomSpacing:12 afterView:root.arrangedSubviews.lastObject];

    // ② 归档信息
    [root addArrangedSubview:[self sectionLabel:@"归档信息"]];

    self.datePicker = [[NSDatePicker alloc] init];
    self.datePicker.datePickerStyle = NSDatePickerStyleTextFieldAndStepper;
    self.datePicker.datePickerElements = NSDatePickerElementFlagYearMonthDay;
    self.datePicker.dateValue = [NSDate date];
    self.datePicker.target = self;
    self.datePicker.action = @selector(formChanged:);
    self.datePicker.translatesAutoresizingMaskIntoConstraints = NO;
    [self.datePicker.widthAnchor constraintEqualToConstant:132].active = YES;
    [self.datePicker setContentHuggingPriority:800 forOrientation:NSLayoutConstraintOrientationHorizontal];
    self.autoDateCheck = [NSButton checkboxWithTitle:@"自动日期" target:self action:@selector(autoDateToggled:)];
    self.autoDateCheck.state = NSControlStateValueOn;
    self.autoDateCheck.translatesAutoresizingMaskIntoConstraints = NO;
    self.autoDateCheck.toolTip = @"勾选后日期由照片拍摄时间决定，不能手动填写";
    self.todayButton = [self button:@"今天" action:@selector(useToday:)];
    self.datePicker.enabled = NO;
    self.todayButton.enabled = NO;
    NSStackView *dateRow = [self formRow:@"拍摄日期" control:self.datePicker extra:nil];
    [dateRow addArrangedSubview:self.autoDateCheck];
    [dateRow addArrangedSubview:self.todayButton];
    [dateRow addArrangedSubview:[self gapView]];
    addRow(dateRow);

    self.eventField = [NSTextField textFieldWithString:@""];
    self.eventField.translatesAutoresizingMaskIntoConstraints = NO;
    self.eventField.font = [NSFont systemFontOfSize:13];
    self.eventField.placeholderString = @"如：毕业典礼";
    self.eventField.delegate = self;
    [self.eventField setContentHuggingPriority:1 forOrientation:NSLayoutConstraintOrientationHorizontal];
    addRow([self formRow:@"事件名称" control:self.eventField extra:nil]);

    self.modeControl = [NSSegmentedControl segmentedControlWithLabels:@[ @"嵌套结构", @"并列命名" ]
                                                        trackingMode:NSSegmentSwitchTrackingSelectOne
                                                              target:self
                                                              action:@selector(formChanged:)];
    self.modeControl.selectedSegment = 0;
    self.modeControl.translatesAutoresizingMaskIntoConstraints = NO;
    self.modeHintLabel = [self label:@"嵌套：事件文件夹内分（原始照片）（原始视频）等"
                                font:[NSFont systemFontOfSize:11.5]
                               color:[NSColor tertiaryLabelColor]];
    addRow([self formRow:@"目录结构" control:self.modeControl extra:self.modeHintLabel]);

    self.subsTokenField = [[NSTokenField alloc] init];
    self.subsTokenField.translatesAutoresizingMaskIntoConstraints = NO;
    self.subsTokenField.font = [NSFont systemFontOfSize:13];
    self.subsTokenField.delegate = self;
    self.subsTokenField.placeholderString = @"输入名称后回车，或点「常用」选择";
    self.subsTokenField.tokenizingCharacterSet =
        [NSCharacterSet characterSetWithCharactersInString:@",，\n"];
    [self.subsTokenField setContentHuggingPriority:1 forOrientation:NSLayoutConstraintOrientationHorizontal];
    [self.subsTokenField setContentCompressionResistancePriority:250
                                                    forOrientation:NSLayoutConstraintOrientationHorizontal];

    self.subsMenuButton = [self button:@"常用 ▾" action:@selector(showSubfolderMenu:)];
    self.subsMenuButton.toolTip = @"从预设或最近常用的子文件夹中选择";
    NSTextField *subsHint = [self label:@"原始照片 / 视频自动"
                                   font:[NSFont systemFontOfSize:11]
                                  color:[NSColor tertiaryLabelColor]];
    addRow([self formRow:@"子文件夹"
                 control:[self rowWithViews:@[ self.subsTokenField, self.subsMenuButton, subsHint ]]
                   extra:nil]);

    self.signCheck = [NSButton checkboxWithTitle:@"手动署名" target:self action:@selector(signToggled:)];
    self.signCheck.translatesAutoresizingMaskIntoConstraints = NO;
    self.signField = [NSTextField textFieldWithString:@""];
    self.signField.translatesAutoresizingMaskIntoConstraints = NO;
    self.signField.font = [NSFont systemFontOfSize:13];
    self.signField.placeholderString = @"如：张三";
    self.signField.delegate = self;
    self.signField.enabled = NO;
    [self.signField setContentHuggingPriority:1 forOrientation:NSLayoutConstraintOrientationHorizontal];
    [self.signField.widthAnchor constraintGreaterThanOrEqualToConstant:130].active = YES;

    self.autoSignCheck = [NSButton checkboxWithTitle:@"自动署名" target:self action:@selector(autoSignToggled:)];
    self.autoSignCheck.translatesAutoresizingMaskIntoConstraints = NO;
    self.autoSignCheck.state = NSControlStateValueOn;

    self.autoSignStatusView = [[StatusChipView alloc] init];
    self.autoSignStatusView.translatesAutoresizingMaskIntoConstraints = NO;
    [self.autoSignStatusView.widthAnchor constraintEqualToConstant:118].active = YES;
    [self.autoSignStatusView.heightAnchor constraintEqualToConstant:22].active = YES;

    self.rulesButton = [self button:@"署名规则…" action:@selector(showRules:)];
    addRow([self formRow:@"署名"
                 control:[self rowWithViews:@[ self.signCheck, self.signField,
                                               self.autoSignCheck, self.autoSignStatusView,
                                               self.rulesButton ]]
                   extra:nil]);

    self.personModeControl = [NSSegmentedControl segmentedControlWithLabels:@[ @"单人模式", @"多人模式" ]
                                                              trackingMode:NSSegmentSwitchTrackingSelectOne
                                                                    target:self
                                                                    action:@selector(personModeChanged:)];
    self.personModeControl.selectedSegment = 0;
    self.personModeControl.translatesAutoresizingMaskIntoConstraints = NO;
    self.personModeHintLabel = [self label:@"多人：原始照片/视频内按人名再分一层"
                                      font:[NSFont systemFontOfSize:11]
                                     color:[NSColor tertiaryLabelColor]];
    addRow([self formRow:@"人员模式" control:self.personModeControl
                   extra:self.personModeHintLabel]);

    [root setCustomSpacing:12 afterView:root.arrangedSubviews.lastObject];

    // ③ 预览
    [root addArrangedSubview:[self sectionLabel:@"将创建"]];

    NSScrollView *scroll = [[NSScrollView alloc] init];
    scroll.translatesAutoresizingMaskIntoConstraints = NO;
    scroll.hasVerticalScroller = YES;
    scroll.autohidesScrollers = YES;
    scroll.borderType = NSNoBorder;
    scroll.drawsBackground = YES;
    scroll.backgroundColor = [NSColor controlBackgroundColor];
    scroll.wantsLayer = YES;
    scroll.layer.cornerRadius = 8;
    scroll.layer.borderWidth = 1;
    scroll.layer.borderColor = [NSColor separatorColor].CGColor;

    self.treeStack = [FlippedStackView new];
    self.treeStack.orientation = NSUserInterfaceLayoutOrientationVertical;
    self.treeStack.alignment = NSLayoutAttributeLeading;
    self.treeStack.spacing = 4;
    self.treeStack.translatesAutoresizingMaskIntoConstraints = NO;
    self.treeScrollView = scroll;
    scroll.documentView = self.treeStack;
    [NSLayoutConstraint activateConstraints:@[
        [self.treeStack.leadingAnchor constraintEqualToAnchor:scroll.contentView.leadingAnchor constant:10],
        [self.treeStack.trailingAnchor constraintEqualToAnchor:scroll.contentView.trailingAnchor constant:-10],
        [self.treeStack.topAnchor constraintEqualToAnchor:scroll.contentView.topAnchor constant:10],
    ]];
    NSLayoutConstraint *preferredTreeHeight =
        [scroll.heightAnchor constraintEqualToConstant:200];
    preferredTreeHeight.priority = 750;
    preferredTreeHeight.active = YES;
    [scroll.heightAnchor constraintGreaterThanOrEqualToConstant:120].active = YES;
    [scroll setContentHuggingPriority:800 forOrientation:NSLayoutConstraintOrientationVertical];
    [scroll setContentCompressionResistancePriority:250 forOrientation:NSLayoutConstraintOrientationVertical];
    addRow(scroll);
    [root setCustomSpacing:12 afterView:scroll];

    // ④ 照片导入
    [root addArrangedSubview:[self sectionLabel:@"照片导入（可选）"]];

    self.folderButton = [self button:@"选择照片文件夹…" action:@selector(choosePhotoFolder:)];
    self.filesButton = [self button:@"选择照片…" action:@selector(choosePhotoFiles:)];
    self.sourceLabel = [self label:@"未选择照片 · 可直接拖入"
                              font:[NSFont systemFontOfSize:11.5]
                             color:[NSColor tertiaryLabelColor]];
    [self.sourceLabel setContentCompressionResistancePriority:250 forOrientation:NSLayoutConstraintOrientationHorizontal];
    addRow([self rowWithViews:@[ self.folderButton, self.filesButton, self.sourceLabel ]]);

    self.metaGrid = [NSStackView new];
    self.metaGrid.orientation = NSUserInterfaceLayoutOrientationVertical;
    self.metaGrid.alignment = NSLayoutAttributeLeading;
    self.metaGrid.spacing = 2;
    self.metaGrid.translatesAutoresizingMaskIntoConstraints = NO;
    self.metaGrid.hidden = YES;
    addRow(self.metaGrid);

    self.autoSignNoteLabel = [self label:@""
                                     font:[NSFont systemFontOfSize:11.5]
                                    color:[NSColor tertiaryLabelColor]];
    self.autoSignNoteLabel.hidden = YES;
    addRow(self.autoSignNoteLabel);

    self.radioCopy = [NSButton radioButtonWithTitle:@"复制" target:self action:@selector(methodChanged:)];
    self.radioCopy.state = NSControlStateValueOn;
    self.radioCopy.translatesAutoresizingMaskIntoConstraints = NO;
    self.moveRadio = [NSButton radioButtonWithTitle:@"移动" target:self action:@selector(methodChanged:)];
    self.moveRadio.translatesAutoresizingMaskIntoConstraints = NO;
    self.verifyCheck = [NSButton checkboxWithTitle:@"写入后校验" target:self action:@selector(verifyToggled:)];
    self.verifyCheck.translatesAutoresizingMaskIntoConstraints = NO;
    self.verifyCheck.toolTip = @"复制或移动都会比对源文件与目标文件的哈希；移动会先复制、校验通过后再删除源文件";
    self.verifyKindPopup = [[NSPopUpButton alloc] initWithFrame:NSZeroRect pullsDown:NO];
    [self.verifyKindPopup addItemsWithTitles:@[ @"xxHash64（快）", @"MD5（通用）" ]];
    [self.verifyKindPopup itemAtIndex:0].tag = 0;
    [self.verifyKindPopup itemAtIndex:1].tag = 1;
    self.verifyKindPopup.translatesAutoresizingMaskIntoConstraints = NO;
    self.verifyKindPopup.enabled = NO;

    NSStackView *methodControl = [self rowWithViews:@[
        self.radioCopy, self.moveRadio, [self fixedSpacer:12],
        self.verifyCheck, self.verifyKindPopup, [self gapView]
    ]];
    NSStackView *methodRow = [self formRow:@"处理方式" control:methodControl extra:nil];
    methodRow.toolTip = @"图片/RAW 进（原始照片），视频/音频进（原始视频）";
    addRow(methodRow);

    self.sourceTagCheck = [NSButton checkboxWithTitle:@"打标签" target:self action:@selector(tagToggled:)];
    self.sourceTagCheck.translatesAutoresizingMaskIntoConstraints = NO;
    self.sourceTagCombo = [[NSComboBox alloc] init];
    [self.sourceTagCombo addItemsWithObjectValues:SourceTagPresets()];
    self.sourceTagCombo.editable = YES;
    self.sourceTagCombo.completes = YES;
    self.sourceTagCombo.placeholderString = @"来源，如：拷卡";
    self.sourceTagCombo.font = [NSFont systemFontOfSize:12.5];
    self.sourceTagCombo.translatesAutoresizingMaskIntoConstraints = NO;
    self.sourceTagCombo.enabled = NO;
    self.sourceTagCombo.target = self;
    self.sourceTagCombo.action = @selector(tagChanged:);
    [self.sourceTagCombo.widthAnchor constraintEqualToConstant:150].active = YES;
    self.sourceTagCheck.toolTip = @"有署名时加在署名后面，如：张三_拷卡；多人模式下加在人名后面";
    self.sourceTagCombo.toolTip = self.sourceTagCheck.toolTip;

    NSMutableArray *chips = [NSMutableArray array];
    NSMutableArray<NSTextField *> *labels = [NSMutableArray array];
    NSArray *titles = CategoryTitles();
    NSArray *colors = @[ [NSColor systemBlueColor], [NSColor systemOrangeColor],
                         [NSColor systemPurpleColor], [NSColor systemGreenColor] ];
    for (NSUInteger i = 0; i < titles.count; i++) {
        NSTextField *chipLabel = nil;
        [chips addObject:[self categoryChipWithTitle:titles[i]
                                               color:colors[i]
                                                label:&chipLabel]];
        [labels addObject:chipLabel];
    }
    self.categoryLabels = labels;

    NSStackView *tagRow = [self formRow:@"来源标签"
                                control:[self rowWithViews:@[ self.sourceTagCheck,
                                                              self.sourceTagCombo,
                                                              [self gapView] ]]
                                  extra:nil];
    tagRow.hidden = YES;
    self.sourceTagRow = tagRow;
    addRow(tagRow);

    NSMutableArray *chipViews = [chips mutableCopy];
    [chipViews addObject:[self gapView]];
    NSStackView *categoryRow = [self formRow:@"文件构成"
                                    control:[self rowWithViews:chipViews]
                                      extra:nil];
    categoryRow.hidden = YES;
    self.categoryRow = categoryRow;
    addRow(categoryRow);

    // 操作按钮
    [root setCustomSpacing:10 afterView:methodRow];
    self.createButton = [self button:@"创建文件夹" action:@selector(createFolders:)];
    self.createButton.keyEquivalent = @"\r";
    self.createButton.bezelColor = [NSColor controlAccentColor];
    self.createButton.font = [NSFont systemFontOfSize:13 weight:NSFontWeightMedium];
    self.createButton.controlSize = NSControlSizeLarge;

    self.importButton = [self button:@"导入照片" action:@selector(importPhotos:)];
    self.importButton.controlSize = NSControlSizeLarge;
    self.importButton.enabled = NO;

    self.revealButton = [self button:@"在 Finder 中显示" action:@selector(revealInFinder:)];
    self.revealButton.enabled = NO;

    self.spinner = [[NSProgressIndicator alloc] init];
    self.spinner.style = NSProgressIndicatorStyleSpinning;
    self.spinner.controlSize = NSControlSizeSmall;
    self.spinner.translatesAutoresizingMaskIntoConstraints = NO;
    self.spinner.hidden = YES;
    [self.spinner.widthAnchor constraintEqualToConstant:16].active = YES;
    [self.spinner.heightAnchor constraintEqualToConstant:16].active = YES;

    self.progress = [[NSProgressIndicator alloc] init];
    self.progress.style = NSProgressIndicatorStyleBar;
    self.progress.indeterminate = NO;
    self.progress.minValue = 0;
    self.progress.maxValue = 1;
    self.progress.translatesAutoresizingMaskIntoConstraints = NO;
    self.progress.hidden = YES;
    [self.progress.widthAnchor constraintEqualToConstant:160].active = YES;

    NSStackView *actions = [self rowWithViews:@[ self.createButton, self.importButton, self.revealButton ]];
    [actions setCustomSpacing:14 afterView:self.importButton];
    [root addArrangedSubview:actions];

    self.statusLabel = [self label:@"准备就绪"
                              font:[NSFont systemFontOfSize:11.5]
                             color:[NSColor secondaryLabelColor]];

    self.verifyResultChip = [[StatusChipView alloc] init];
    self.verifyResultChip.translatesAutoresizingMaskIntoConstraints = NO;
    self.verifyResultChip.hidden = YES;
    [self.verifyResultChip.widthAnchor constraintEqualToConstant:110].active = YES;
    [self.verifyResultChip.heightAnchor constraintEqualToConstant:20].active = YES;

    NSStackView *statusRow = [self rowWithViews:@[ self.spinner, self.progress,
                                                   self.verifyResultChip, self.statusLabel ]];
    addRow(statusRow);
    [root setCustomSpacing:6 afterView:actions];
    [self.statusLabel setContentCompressionResistancePriority:250 forOrientation:NSLayoutConstraintOrientationHorizontal];

    [self.window layoutIfNeeded];
    NSSize fit = root.fittingSize;
    CGFloat contentWidth = MAX(780.0, fit.width + 52.0);
    CGFloat contentHeight = fit.height + 32.0;
    NSScreen *screen = self.window.screen ?: [NSScreen mainScreen];
    CGFloat maxHeight = screen.visibleFrame.size.height - 16.0;
    if (contentHeight > maxHeight) contentHeight = maxHeight;
    [self.window setContentSize:NSMakeSize(contentWidth, contentHeight)];
}

#pragma mark 设置持久化

- (void)restoreSettings {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    NSString *root = [d stringForKey:kKeyRoot];
    if (!root.length) root = [NSHomeDirectory() stringByAppendingPathComponent:@"Pictures/自动归档"];
    self.rootField.stringValue = root;

    NSString *event = [d stringForKey:kKeyEvent];
    if (event.length) self.eventField.stringValue = event;

    NSString *mode = [d stringForKey:kKeyMode];
    self.modeControl.selectedSegment = [mode isEqualToString:@"flat"] ? 1 : 0;

    NSArray *selected = nil;
    NSString *subsJSON = [d stringForKey:kKeySubsSelected];
    if (subsJSON.length) {
        id object = [NSJSONSerialization JSONObjectWithData:[subsJSON dataUsingEncoding:NSUTF8StringEncoding]
                                                    options:0 error:NULL];
        if ([object isKindOfClass:[NSArray class]]) selected = object;
    }
    if (!selected) {
        NSString *legacy = [d stringForKey:kKeySubs];
        selected = legacy.length ? ParseSubfolders(legacy) : SubfolderPresets();
    }
    NSMutableArray *extras = [NSMutableArray array];
    for (id value in selected) {
        NSString *name = [value description];
        if ([name isEqualToString:kOriginalPhotoName] ||
            [name isEqualToString:kOriginalVideoName] ||
            [name isEqualToString:@"（原始）"]) {
            continue;
        }
        [extras addObject:name];
    }
    [self setSelectedSubfolders:extras];
    [self loadSubfolderRecents];

    BOOL move = [d boolForKey:@"move"];
    self.moveRadio.state = move ? NSControlStateValueOn : NSControlStateValueOff;
    self.radioCopy.state = move ? NSControlStateValueOff : NSControlStateValueOn;

    BOOL hasManualKey = ([d objectForKey:kKeyManualSignOn] != nil);
    BOOL manualOn = hasManualKey ? [d boolForKey:kKeyManualSignOn] : [d boolForKey:kKeySignOn];
    NSString *manualText = [d stringForKey:kKeyManualSignText];
    if (!manualText.length) manualText = [d stringForKey:kKeySignText] ?: @"";
    self.signCheck.state = manualOn ? NSControlStateValueOn : NSControlStateValueOff;
    self.signField.stringValue = manualText;
    self.signField.enabled = manualOn;

    BOOL hasAutoKey = ([d objectForKey:kKeyAutoSignOn] != nil);
    BOOL autoOn = hasAutoKey ? [d boolForKey:kKeyAutoSignOn] : YES;
    self.autoSignCheck.state = autoOn ? NSControlStateValueOn : NSControlStateValueOff;

    self.multiPerson = [d boolForKey:kKeyMultiPerson];
    self.personModeControl.selectedSegment = self.multiPerson ? 1 : 0;
    [self loadSignRules];

    BOOL hasAutoDateKey = ([d objectForKey:kKeyAutoDate] != nil);
    BOOL autoDateOn = hasAutoDateKey ? [d boolForKey:kKeyAutoDate] : YES;
    self.autoDateCheck.state = autoDateOn ? NSControlStateValueOn : NSControlStateValueOff;
    self.datePicker.enabled = !autoDateOn;
    self.todayButton.enabled = !autoDateOn;

    double savedDate = [d doubleForKey:kKeyLastDate];
    if (savedDate > 0) {
        self.datePicker.dateValue = [NSDate dateWithTimeIntervalSince1970:savedDate];
    }

    BOOL tagOn = [d boolForKey:kKeyTagOn];
    self.sourceTagCheck.state = tagOn ? NSControlStateValueOn : NSControlStateValueOff;
    self.sourceTagCombo.stringValue = [d stringForKey:kKeyTagText] ?: @"";
    self.sourceTagCombo.enabled = tagOn;

    BOOL verifyOn = [d boolForKey:kKeyVerifyOn];
    self.verifyCheck.state = verifyOn ? NSControlStateValueOn : NSControlStateValueOff;
    self.verifyKindPopup.enabled = verifyOn;
    NSInteger verifyKind = [d integerForKey:kKeyVerifyKind];
    [self.verifyKindPopup selectItemAtIndex:(verifyKind == 1) ? 1 : 0];
}

- (void)saveSettings {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    [d setObject:self.rootField.stringValue forKey:kKeyRoot];
    [d setObject:self.eventField.stringValue forKey:kKeyEvent];
    [d setObject:(self.modeControl.selectedSegment == 1 ? @"flat" : @"nested") forKey:kKeyMode];
    NSData *subsData = [NSJSONSerialization dataWithJSONObject:[self selectedSubfolders]
                                                       options:0 error:NULL];
    NSString *subsJSON = subsData ? [[NSString alloc] initWithData:subsData encoding:NSUTF8StringEncoding] : @"[]";
    [d setObject:(subsJSON ?: @"[]") forKey:kKeySubsSelected];
    [d setBool:(self.moveRadio.state == NSControlStateValueOn) forKey:@"move"];
    [d setBool:(self.signCheck.state == NSControlStateValueOn) forKey:kKeyManualSignOn];
    [d setObject:(self.signField.stringValue ?: @"") forKey:kKeyManualSignText];
    [d setBool:(self.autoSignCheck.state == NSControlStateValueOn) forKey:kKeyAutoSignOn];
    [d setBool:self.multiPerson forKey:kKeyMultiPerson];
    [d setBool:(self.autoDateCheck.state == NSControlStateValueOn) forKey:kKeyAutoDate];
    [d setDouble:self.datePicker.dateValue.timeIntervalSince1970 forKey:kKeyLastDate];
    [d setBool:(self.sourceTagCheck.state == NSControlStateValueOn) forKey:kKeyTagOn];
    [d setObject:(self.sourceTagCombo.stringValue ?: @"") forKey:kKeyTagText];
    [d setBool:(self.verifyCheck.state == NSControlStateValueOn) forKey:kKeyVerifyOn];
    [d setInteger:self.verifyKindPopup.selectedTag forKey:kKeyVerifyKind];
}

#pragma mark 状态与预览

- (NSString *)expandedRootPath {
    NSString *p = Trim(self.rootField.stringValue);
    if (!p.length) p = [NSHomeDirectory() stringByAppendingPathComponent:@"Pictures/自动归档"];
    p = [p stringByExpandingTildeInPath];
    return [p stringByStandardizingPath];
}

- (ArchivePlan *)currentPlan {
    ArchivePlan *plan = [ArchivePlan new];
    plan.rootURL = [NSURL fileURLWithPath:[self expandedRootPath] isDirectory:YES];
    plan.date = self.datePicker.dateValue ?: [NSDate date];
    plan.event = self.eventField.stringValue;
    plan.flatMode = (self.modeControl.selectedSegment == 1);
    plan.subfolders = [self selectedSubfolders];
    plan.manualSignature = (self.signCheck.state == NSControlStateValueOn) ? self.signField.stringValue : @"";
    plan.autoSignature = self.autoSignature;
    plan.autoSignEnabled = (self.autoSignCheck.state == NSControlStateValueOn);
    plan.multiPerson = self.multiPerson;
    plan.includesVideo = self.batchHasVideo;
    plan.sourceTag = (self.multiPerson &&
                     self.sourceTagCheck.state == NSControlStateValueOn) ? self.sourceTagCombo.stringValue : @"";
    plan.verifyCopies = (self.verifyCheck.state == NSControlStateValueOn);
    plan.verifyKind = (self.verifyKindPopup.selectedTag == 1) ? 1 : 0;
    plan.photoAuthors = self.detectedPhotoAuthors ?: @[];
    plan.videoAuthors = self.detectedVideoAuthors ?: @[];
    return plan;
}

- (BOOL)currentEventFolderExists {
    ArchivePlan *plan = [self currentPlan];
    NSURL *url = plan.flatMode ? [plan originalPhotoDirectoryURL] : [plan eventDirectoryURL];
    return url && [[NSFileManager defaultManager] fileExistsAtPath:url.path];
}

/// 自动日期：文件夹尚未建立时采用本批最早日期；已建立则保持不变，日期不符时提示。
- (AutoDateResult)applyAutoDateFromItems:(NSArray<MediaItem *> *)items showAlert:(BOOL)showAlert {
    NSDate *earliest = nil;
    NSMutableArray<NSString *> *days = [NSMutableArray array];
    for (MediaItem *item in items) {
        if ([AudioExtensions() containsObject:item.url.pathExtension.lowercaseString]) continue;
        if (!item.meta.date) continue;
        if (!earliest || [item.meta.date compare:earliest] == NSOrderedAscending) {
            earliest = item.meta.date;
        }
        NSString *key = DayKey(item.meta.date);
        if (key.length && ![days containsObject:key]) [days addObject:key];
    }
    if (!earliest) return AutoDateResultNone;

    if (![self currentEventFolderExists]) {
        self.datePicker.dateValue = earliest;
        [self refreshPreview];
        return AutoDateResultAdopted;
    }

    NSString *currentKey = DayKey(self.datePicker.dateValue);
    if ([days containsObject:currentKey]) return AutoDateResultNone;

    if (showAlert) {
        [days sortUsingSelector:@selector(localizedStandardCompare:)];
        NSString *list = [days componentsJoinedByString:@"、"];
        NSAlert *alert = [NSAlert new];
        alert.messageText = @"拍摄日期与归档日期不一致";
        alert.informativeText = [NSString stringWithFormat:
            @"新照片的拍摄日期是 %@，当前归档文件夹的日期是 %@。\n已保持原日期不变；如需调整，请先取消勾选「自动日期」。",
            list, currentKey];
        alert.alertStyle = NSAlertStyleInformational;
        [alert addButtonWithTitle:@"好"];
        [alert beginSheetModalForWindow:self.window completionHandler:nil];
    }
    return AutoDateResultMismatch;
}

- (void)refreshPreview {
    [self updatePersonModeLock];
    ArchivePlan *plan = [self currentPlan];
    [self rebuildTreeForPlan:plan];
    self.modeHintLabel.stringValue = plan.flatMode
        ? @"并列：26.10.19毕业典礼（原始照片）…"
        : @"嵌套：事件文件夹内分（原始照片）（原始视频）等";
}

- (void)formChanged:(id)sender {
    [self refreshPreview];
}

- (void)controlTextDidChange:(NSNotification *)note {
    if ([note.object isKindOfClass:[NSTextField class]]) {
        NSTextField *field = note.object;
        if (field.tag >= 1000) return;  // 目录树里的编辑，不要在输入过程中重建
    }
    if (note.object == self.signField) [self refreshAutoSignatureStatus];
    [self refreshPreview];
}

- (void)signToggled:(id)sender {
    self.signField.enabled = (self.signCheck.state == NSControlStateValueOn);
    [self refreshAutoSignatureStatus];
    [self refreshPreview];
    if (self.signCheck.state == NSControlStateValueOn && self.autoSignature.length) {
        [self maybeShowSignatureConflict];
    }
}

- (void)autoSignToggled:(id)sender {
    [self computeDerivedSignatureState];
}

- (NSView *)categoryChipWithTitle:(NSString *)title
                            color:(NSColor *)color
                             label:(NSTextField **)outLabel {
    NSView *chip = [NSView new];
    chip.translatesAutoresizingMaskIntoConstraints = NO;
    chip.wantsLayer = YES;
    chip.layer.cornerRadius = 6;
    chip.layer.backgroundColor = [color colorWithAlphaComponent:0.14].CGColor;
    [chip setContentHuggingPriority:800 forOrientation:NSLayoutConstraintOrientationHorizontal];

    NSTextField *label = [self label:[NSString stringWithFormat:@"%@ 0", title]
                                font:[NSFont systemFontOfSize:11.5]
                               color:[NSColor labelColor]];
    label.translatesAutoresizingMaskIntoConstraints = NO;
    [chip addSubview:label];
    [NSLayoutConstraint activateConstraints:@[
        [label.leadingAnchor constraintEqualToAnchor:chip.leadingAnchor constant:8],
        [label.trailingAnchor constraintEqualToAnchor:chip.trailingAnchor constant:-8],
        [label.topAnchor constraintEqualToAnchor:chip.topAnchor constant:3],
        [label.bottomAnchor constraintEqualToAnchor:chip.bottomAnchor constant:-3],
    ]];
    if (outLabel) *outLabel = label;
    return chip;
}

- (void)updateCategoryCounts:(NSArray<NSNumber *> *)counts {
    NSArray *titles = CategoryTitles();
    for (NSUInteger i = 0; i < self.categoryLabels.count; i++) {
        NSInteger count = (i < counts.count) ? counts[i].integerValue : 0;
        self.categoryLabels[i].stringValue =
            [NSString stringWithFormat:@"%@ %ld", titles[i], (long)count];
    }
}

- (void)verifyToggled:(id)sender {
    BOOL on = (self.verifyCheck.state == NSControlStateValueOn);
    self.verifyKindPopup.enabled = on;
}

- (void)tagToggled:(id)sender {
    BOOL on = (self.sourceTagCheck.state == NSControlStateValueOn) && self.multiPerson;
    self.sourceTagCombo.enabled = on;
    [self updateSourceTagAvailability];
    [self refreshPreview];
}

- (void)tagChanged:(id)sender {
    [self refreshPreview];
}

- (void)autoDateToggled:(id)sender {
    BOOL on = (self.autoDateCheck.state == NSControlStateValueOn);
    self.datePicker.enabled = !on;
    self.todayButton.enabled = !on;
    if (on && self.items.count) {
        [self applyAutoDateFromItems:self.items showAlert:YES];
    }
    [self refreshPreview];
}

- (void)updateSourceTagAvailability {
    if (!self.sourceTagCheck || !self.sourceTagCombo) return;
    BOOL multi = self.multiPerson;
    self.sourceTagCheck.enabled = multi;
    self.sourceTagCombo.enabled = multi &&
        (self.sourceTagCheck.state == NSControlStateValueOn);
    self.sourceTagCheck.toolTip = multi
        ? @"多人模式下加在人名后面，如：张三_拷卡"
        : @"来源标签只在多人模式下生效";
    self.sourceTagCombo.toolTip = self.sourceTagCheck.toolTip;
}

- (void)updatePersonModeLock {
    if (!self.personModeControl || !self.personModeHintLabel) return;

    ArchivePlan *plan = [self currentPlan];
    NSURL *eventURL = plan.flatMode ? [plan originalPhotoDirectoryURL] : [plan eventDirectoryURL];
    BOOL exists = eventURL &&
        [[NSFileManager defaultManager] fileExistsAtPath:eventURL.path isDirectory:NULL];

    if (!exists) {
        self.personModeLocked = NO;
        self.personModeControl.enabled = YES;
        self.personModeControl.selectedSegment = self.multiPerson ? 1 : 0;
        self.personModeControl.toolTip = nil;
        self.personModeHintLabel.stringValue = @"多人：原始照片/视频内按人名再分一层";
        self.personModeHintLabel.textColor = [NSColor tertiaryLabelColor];
        [self updateSourceTagAvailability];
        return;
    }

    BOOL before = self.multiPerson;
    NSString *stored = [[NSUserDefaults standardUserDefaults]
                        stringForKey:EventModeKey(eventURL.path)];
    if (stored.length) {
        self.multiPerson = [stored isEqualToString:@"multi"];
    } else {
        // 旧目录：有二级子文件夹就按多人处理，否则单人
        BOOL hasSubfolders = NO;
        for (NSString *orig in @[ kOriginalPhotoName, kOriginalVideoName ]) {
            NSURL *dir = [plan directoryURLForFolderName:orig];
            if ([self subfolderNamesInDirectory:dir.path].count) {
                hasSubfolders = YES;
                break;
            }
        }
        self.multiPerson = hasSubfolders;
    }

    self.personModeLocked = YES;
    self.personModeControl.selectedSegment = self.multiPerson ? 1 : 0;
    self.personModeControl.enabled = NO;
    self.personModeControl.toolTip =
        @"事件文件夹已存在，不能修改人员模式；如需更换请先删除事件文件夹";
    self.personModeHintLabel.stringValue = @"目录已创建，人员模式已锁定";
    self.personModeHintLabel.textColor = [NSColor secondaryLabelColor];
    [self updateSourceTagAvailability];

    if (before != self.multiPerson) {
        [self computeDerivedSignatureState];
    }
}

- (void)personModeChanged:(id)sender {
    if (self.personModeLocked) {
        self.personModeControl.selectedSegment = self.multiPerson ? 1 : 0;
        return;
    }
    self.multiPerson = (self.personModeControl.selectedSegment == 1);
    [self updateSourceTagAvailability];
    [self computeDerivedSignatureState];
    [self refreshPreview];
    [self setStatus:(self.multiPerson
        ? @"多人模式：原始照片 / 原始视频 内会按人名再分一层"
        : @"单人模式：原始照片 / 原始视频 下不再分文件夹")];
}

- (BOOL)validateSignature {
    if (self.signCheck.state == NSControlStateValueOn &&
        !Trim(self.signField.stringValue).length) {
        ShowError(self.window, @"请填写署名",
                  @"已勾选「手动署名」，但署名内容为空。\n填写署名，或取消勾选后再试。");
        return NO;
    }
    return YES;
}

- (void)methodChanged:(id)sender {
    if (sender == self.radioCopy) {
        self.moveRadio.state = NSControlStateValueOff;
    } else {
        self.radioCopy.state = NSControlStateValueOff;
    }
}

- (void)useToday:(id)sender {
    self.datePicker.dateValue = [NSDate date];
    [self refreshPreview];
}

- (void)setStatus:(NSString *)text {
    self.statusLabel.stringValue = text ?: @"";
    self.statusLabel.toolTip = text;
}

- (void)setBusy:(BOOL)busy {
    _busy = busy;
    self.createButton.enabled = !busy;
    self.importButton.enabled = !busy && self.items.count > 0;
    self.folderButton.enabled = !busy;
    self.filesButton.enabled = !busy;
    self.spinner.hidden = !busy;
    if (busy) {
        [self.spinner startAnimation:nil];
    } else {
        [self.spinner stopAnimation:nil];
        self.progress.hidden = YES;
    }
}

#pragma mark 选择目录/照片

- (void)chooseRootDirectory:(id)sender {
    NSOpenPanel *panel = [NSOpenPanel openPanel];
    panel.canChooseFiles = NO;
    panel.canChooseDirectories = YES;
    panel.canCreateDirectories = YES;
    panel.allowsMultipleSelection = NO;
    panel.prompt = @"选择";
    panel.message = @"选择归档的根目录";
    NSString *current = [self expandedRootPath];
    if (current.length) panel.directoryURL = [NSURL fileURLWithPath:current isDirectory:YES];

    [panel beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
        if (response != NSModalResponseOK || !panel.URL) return;
        self.rootField.stringValue = panel.URL.path;
        [self refreshPreview];
        [self setStatus:[NSString stringWithFormat:@"归档根目录：%@", AbbreviatePath(panel.URL.path)]];
    }];
}

- (void)choosePhotoFolder:(id)sender {
    NSOpenPanel *panel = [NSOpenPanel openPanel];
    panel.canChooseFiles = NO;
    panel.canChooseDirectories = YES;
    panel.allowsMultipleSelection = NO;
    panel.prompt = @"读取";
    panel.message = @"选择包含照片的文件夹（会递归读取拍摄时间）";

    [panel beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
        if (response != NSModalResponseOK || !panel.URL) return;
        [self loadSources:@[ panel.URL ] description:panel.URL.lastPathComponent];
    }];
}

- (void)choosePhotoFiles:(id)sender {
    NSOpenPanel *panel = [NSOpenPanel openPanel];
    panel.canChooseFiles = YES;
    panel.canChooseDirectories = NO;
    panel.allowsMultipleSelection = YES;
    panel.prompt = @"读取";
    panel.message = @"选择照片文件";

    [panel beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
        if (response != NSModalResponseOK || !panel.URLs.count) return;
        [self loadSources:panel.URLs
             description:[NSString stringWithFormat:@"%lu 个文件", (unsigned long)panel.URLs.count]];
    }];
}

- (void)loadSources:(NSArray<NSURL *> *)urls description:(NSString *)description {
    self.dateBeforeScan = self.datePicker.dateValue;
    [self.batchSignatureMappings removeAllObjects];
    [self.batchFolderPersonMappings removeAllObjects];
    [self.promptedUnknownAuthors removeAllObjects];
    self.sourceURLs = urls;
    self.items = @[];
    self.importButton.enabled = NO;
    self.sourceLabel.stringValue = [NSString stringWithFormat:@"%@ · 读取中…", description];
    [self setBusy:YES];
    [self setStatus:@"正在读取拍摄时间…"];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSArray<NSURL *> *files = CollectMediaURLs(urls);
        NSArray<NSURL *> *previewURLs = CollectPreviewURLs(urls);
        NSArray<NSNumber *> *categoryCounts = CountFileCategories(urls);
        NSMutableArray<MediaItem *> *items = [NSMutableArray arrayWithCapacity:files.count];
        for (NSURL *file in files) {
            MediaItem *item = [MediaItem new];
            item.url = file;
            item.meta = MetadataForURL(file);
            [items addObject:item];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            [self didLoadItems:items description:description
                categoryCounts:categoryCounts previewURLs:previewURLs];
        });
    });
}

- (void)didLoadItems:(NSArray<MediaItem *> *)items
         description:(NSString *)description
      categoryCounts:(NSArray<NSNumber *> *)categoryCounts
         previewURLs:(NSArray<NSURL *> *)previewURLs {
    self.items = items;
    self.pendingPreviewURLs = previewURLs ?: @[];
    self.sourceTagRow.hidden = (items.count == 0);
    self.categoryRow.hidden = (items.count == 0);
    [self updateCategoryCounts:categoryCounts];

    BOOL hasVideo = NO;
    for (MediaItem *item in items) {
        if (item.previewFile ||
            [MovieExtensions() containsObject:item.url.pathExtension.lowercaseString] ||
            [AudioExtensions() containsObject:item.url.pathExtension.lowercaseString]) hasVideo = YES;
    }
    self.batchHasVideo = hasVideo;

    [self setBusy:NO];
    self.importButton.enabled = items.count > 0;

    if (!items.count) {
        self.sourceLabel.stringValue = [NSString stringWithFormat:@"%@ · 没有找到照片", description];
        self.metaGrid.hidden = YES;
        self.autoSignNoteLabel.hidden = YES;
        self.sourceTagRow.hidden = YES;
        self.categoryRow.hidden = YES;
        [self setStatus:@"没有找到可归档的照片（支持 jpg/heic/raw/mov 等）"];
        return;
    }

    NSDate *earliest = nil, *latest = nil;
    NSInteger unknown = 0, byFile = 0;
    for (MediaItem *item in items) {
        if (item.previewFile) continue;
        if ([AudioExtensions() containsObject:item.url.pathExtension.lowercaseString]) continue;
        if (!item.meta.date) {
            unknown++;
            continue;
        }
        if (item.meta.dateSource == CaptureSourceFileSystem) byFile++;
        if (!earliest || [item.meta.date compare:earliest] == NSOrderedAscending) earliest = item.meta.date;
        if (!latest || [item.meta.date compare:latest] == NSOrderedDescending) latest = item.meta.date;
    }

    AutoDateResult autoDateResult = AutoDateResultNone;
    if (earliest && self.autoDateCheck.state == NSControlStateValueOn) {
        autoDateResult = [self applyAutoDateFromItems:items showAlert:YES];
    }

    NSDateFormatter *f = [NSDateFormatter new];
    f.locale = [NSLocale localeWithLocaleIdentifier:@"zh_CN"];
    f.dateFormat = @"yyyy-MM-dd HH:mm";
    NSString *range;
    if (earliest && latest && ![earliest isEqualToDate:latest]) {
        BOOL sameDay = [[NSCalendar currentCalendar] isDate:earliest inSameDayAsDate:latest];
        if (sameDay) {
            f.dateFormat = @"HH:mm";
            range = [NSString stringWithFormat:@"%@ ~ %@",
                     [f stringFromDate:earliest], [f stringFromDate:latest]];
            f.dateFormat = @"yyyy-MM-dd HH:mm";
            range = [NSString stringWithFormat:@"%@ ~ %@",
                     [f stringFromDate:earliest], range];
        } else {
            range = [NSString stringWithFormat:@"%@ ~ %@",
                     [f stringFromDate:earliest], [f stringFromDate:latest]];
        }
    } else if (earliest) {
        range = [f stringFromDate:earliest];
    } else {
        range = @"未知";
    }

    self.sourceLabel.stringValue = [NSString stringWithFormat:@"%@ · %lu 个文件", description, (unsigned long)items.count];
    self.sourceLabel.toolTip = items.firstObject.url.path;

    [self updateMetaGridForItems:items];

    NSString *status;
    if (byFile == (NSInteger)items.count) {
        status = [NSString stringWithFormat:@"共 %lu 个文件 · 未读到拍摄时间，已按文件创建时间处理",
                  (unsigned long)items.count];
    } else if (byFile > 0) {
        status = [NSString stringWithFormat:@"共 %lu 个文件 · 拍摄时间 %@ · %ld 个无拍摄时间（按文件创建时间）",
                  (unsigned long)items.count, range, (long)byFile];
    } else if (unknown > 0) {
        status = [NSString stringWithFormat:@"共 %lu 个文件 · 拍摄时间 %@ · %ld 个无法识别日期",
                  (unsigned long)items.count, range, (long)unknown];
    } else {
        status = [NSString stringWithFormat:@"共 %lu 个文件 · 拍摄时间 %@",
                  (unsigned long)items.count, range];
    }
    if (autoDateResult == AutoDateResultAdopted) {
        status = [status stringByAppendingString:@" · 已按最早日期填入归档日期"];
    } else if (autoDateResult == AutoDateResultMismatch) {
        status = [status stringByAppendingString:@" · 新照片日期与归档日期不一致，已保持原日期"];
    }
    [self computeDerivedSignatureState];

    self.autoSignNoteLabel.hidden = YES;
    if (!self.multiPerson &&
        self.autoSignCheck.state == NSControlStateValueOn &&
        self.autoSignature.length) {
        self.autoSignNoteLabel.stringValue = [NSString stringWithFormat:@"自动署名：%@", self.autoSignature];
        self.autoSignNoteLabel.hidden = NO;
    }
    [self setStatus:status];

    [self maybeAskKeepPreviewFilesWithCompletion:^{
        [self maybeAskSwitchToMultiPersonWithCompletion:^{
            [self postScanSignaturePrompts];
        }];
    }];
}

- (void)maybeAskKeepPreviewFilesWithCompletion:(void (^)(void))completion {
    NSArray<NSURL *> *previews = self.pendingPreviewURLs ?: @[];
    self.pendingPreviewURLs = @[];

    if (!previews.count) {
        if (completion) completion();
        return;
    }

    const char *env = getenv("DSH_KEEP_PREVIEW");
    if (env) {
        if (atoi(env) != 0) [self addPreviewItems:previews];
        if (completion) completion();
        return;
    }
    if (getenv("DSH_NO_ALERTS")) {
        if (completion) completion();
        return;
    }

    NSString *ext = previews.firstObject.pathExtension.uppercaseString ?: @"";
    NSAlert *alert = [NSAlert new];
    alert.messageText = @"发现预览文件";
    alert.informativeText = [NSString stringWithFormat:
        @"发现 %lu 个 %@ 预览文件（通常是相机生成的低清预览，不影响成片）。\n"
        @"要一起归档吗？不保留会跳过这些文件，不会删除原件。",
        (unsigned long)previews.count, ext];
    alert.alertStyle = NSAlertStyleInformational;
    [alert addButtonWithTitle:@"不保留"];
    [alert addButtonWithTitle:@"保留"];
    [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
        if (response == NSAlertSecondButtonReturn) {
            [self addPreviewItems:previews];
        }
        if (completion) completion();
    }];
}

- (void)addPreviewItems:(NSArray<NSURL *> *)urls {
    if (!urls.count) return;

    NSMutableDictionary<NSString *, MediaItem *> *byBase = [NSMutableDictionary dictionary];
    for (MediaItem *item in self.items) {
        if (item.previewFile || !item.url.path) continue;
        NSString *base = item.url.path.stringByDeletingPathExtension.lowercaseString;
        if (base.length) byBase[base] = item;
    }

    NSMutableArray<MediaItem *> *items = [self.items mutableCopy];
    for (NSURL *url in urls) {
        MediaItem *item = [MediaItem new];
        item.url = url;
        item.previewFile = YES;
        MediaItem *paired = byBase[url.path.stringByDeletingPathExtension.lowercaseString];
        item.meta = paired.meta ?: MetadataForURL(url);
        [items addObject:item];
    }

    self.items = items;
    self.batchHasVideo = YES;
    [self computeDerivedSignatureState];
    [self refreshPreview];
    [self setStatus:[NSString stringWithFormat:@"已保留 %lu 个预览文件（随视频归档）",
                     (unsigned long)urls.count]];
}




#pragma mark 目录树（可直接编辑）

- (NSView *)fixedSpacer:(CGFloat)width {
    NSView *view = [NSView new];
    view.translatesAutoresizingMaskIntoConstraints = NO;
    [view.widthAnchor constraintEqualToConstant:width].active = YES;
    [view.heightAnchor constraintEqualToConstant:1].active = YES;
    return view;
}

- (NSTextField *)treeConnectorLabel:(NSString *)text {
    NSTextField *label = [self label:text
                                font:[NSFont monospacedSystemFontOfSize:12 weight:NSFontWeightRegular]
                               color:[NSColor tertiaryLabelColor]];
    [label.widthAnchor constraintEqualToConstant:30].active = YES;
    return label;
}

- (NSTextField *)treeBadge:(NSString *)text {
    return [self label:text font:[NSFont systemFontOfSize:10.5] color:[NSColor tertiaryLabelColor]];
}

- (NSURL *)eventFolderURLForPlan:(ArchivePlan *)plan {
    return [plan.rootURL URLByAppendingPathComponent:[plan baseName] isDirectory:YES];
}

- (NSURL *)subfolderURLForName:(NSString *)name plan:(ArchivePlan *)plan {
    if (plan.flatMode) {
        NSString *folder = [[plan baseName] stringByAppendingString:name];
        return [plan.rootURL URLByAppendingPathComponent:folder isDirectory:YES];
    }
    return [[self eventFolderURLForPlan:plan] URLByAppendingPathComponent:name isDirectory:YES];
}

- (void)addTreeRow:(NSView *)row {
    [self.treeStack addArrangedSubview:row];
    [row.widthAnchor constraintEqualToAnchor:self.treeStack.widthAnchor].active = YES;
}

- (void)rebuildTreeForPlan:(ArchivePlan *)plan {
    if (self.rebuildingTree) return;
    self.rebuildingTree = YES;
    self.pendingNewField = nil;

    for (NSView *view in [self.treeStack.arrangedSubviews copy]) {
        [self.treeStack removeArrangedSubview:view];
        [view removeFromSuperview];
    }

    NSFileManager *fm = [NSFileManager defaultManager];

    // 根目录
    NSMutableArray *rootViews = [NSMutableArray arrayWithObject:[self fixedSpacer:4]];
    [rootViews addObject:[self label:[AbbreviatePath(plan.rootURL.path) stringByAppendingString:@"/"]
                                font:[NSFont systemFontOfSize:12.5]
                               color:[NSColor secondaryLabelColor]]];
    [rootViews addObject:[self gapView]];
    [self addTreeRow:[self rowWithViews:rootViews]];

    NSArray<NSString *> *originals = [plan originalFolderNames];
    NSArray<NSString *> *extras = [plan effectiveSubfolders];

    if (!plan.flatMode) {
        NSURL *eventURL = [self eventFolderURLForPlan:plan];
        BOOL exists = [fm fileExistsAtPath:eventURL.path];
        NSMutableArray *views = [NSMutableArray array];
        [views addObject:[self fixedSpacer:18]];
        [views addObject:[self treeConnectorLabel:@"└──"]];
        [views addObject:[self label:[[plan baseName] stringByAppendingString:@"/"]
                                font:[NSFont systemFontOfSize:12.5 weight:NSFontWeightMedium]
                               color:[NSColor labelColor]]];
        if (exists) {
            [views addObject:[self treeBadge:@"已存在"]];
            [views addObject:[self trashButtonForURL:eventURL
                                                name:[plan baseName]
                                            isExtra:NO]];
        }
        [views addObject:[self gapView]];
        [self addTreeRow:[self rowWithViews:views]];
    }

    NSUInteger total = originals.count + extras.count;
    NSUInteger rowIndex = 0;

    for (NSString *name in originals) {
        BOOL last = (rowIndex == total - 1);
        NSURL *url = [plan directoryURLForFolderName:name];
        [self addTreeRow:[self treeOriginalRow:name
                                     connector:(last ? @"└──" : @"├──")
                                      existing:[fm fileExistsAtPath:url.path]
                                          plan:plan]];
        if (plan.multiPerson) {
            [self addPersonRowsForOriginal:name plan:plan];
        }
        rowIndex++;
    }

    for (NSUInteger i = 0; i < extras.count; i++) {
        BOOL last = (rowIndex == total - 1);
        NSURL *url = [self subfolderURLForName:extras[i] plan:plan];
        [self addTreeRow:[self treeSubfolderRow:extras[i]
                                          index:i
                                      connector:(last ? @"└──" : @"├──")
                                       existing:[fm fileExistsAtPath:url.path]
                                           plan:plan]];
        rowIndex++;
    }

    [self addTreeRow:[self treeAddRowForPlan:plan]];
    self.rebuildingTree = NO;

    [self.treeStack layoutSubtreeIfNeeded];
    [self.treeScrollView.contentView scrollToPoint:NSZeroPoint];
    [self.treeScrollView reflectScrolledClipView:self.treeScrollView.contentView];
}

- (NSArray<NSString *> *)personNamesForOriginal:(NSString *)name plan:(ArchivePlan *)plan {
    NSArray<NSString *> *planned = [name isEqualToString:kOriginalPhotoName]
        ? [plan authorFolderNames]
        : [plan videoAuthorNames];

    NSMutableArray<NSString *> *persons = [NSMutableArray array];
    for (NSString *person in planned) {
        if (![persons containsObject:person]) [persons addObject:person];
    }
    NSURL *dir = [plan directoryURLForFolderName:name];
    for (NSString *sub in [self subfolderNamesInDirectory:dir.path]) {
        if (![persons containsObject:sub]) [persons addObject:sub];
    }
    [persons sortUsingComparator:^NSComparisonResult(NSString *a, NSString *b) {
        if ([a isEqualToString:kUnknownAuthorName]) return NSOrderedDescending;
        if ([b isEqualToString:kUnknownAuthorName]) return NSOrderedAscending;
        return [a localizedStandardCompare:b];
    }];
    return persons;
}

- (void)addPersonRowsForOriginal:(NSString *)name plan:(ArchivePlan *)plan {
    NSArray<NSString *> *persons = [self personNamesForOriginal:name plan:plan];
    if (!persons.count) return;

    NSURL *dir = [plan directoryURLForFolderName:name];
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSUInteger i = 0; i < persons.count; i++) {
        BOOL last = (i == persons.count - 1);
        NSURL *personURL = [dir URLByAppendingPathComponent:persons[i] isDirectory:YES];
        [self addTreeRow:[self treePersonRow:persons[i]
                                    connector:(last ? @"└──" : @"├──")
                                     existing:[fm fileExistsAtPath:personURL.path]
                                          URL:personURL]];
    }
}

- (NSView *)treePersonRow:(NSString *)person
                connector:(NSString *)connector
                 existing:(BOOL)exists
                      URL:(NSURL *)url {
    NSMutableArray *views = [NSMutableArray array];
    [views addObject:[self fixedSpacer:66]];
    [views addObject:[self treeConnectorLabel:connector]];
    [views addObject:[self label:[person stringByAppendingString:@"/"]
                            font:[NSFont systemFontOfSize:12]
                           color:[NSColor secondaryLabelColor]]];
    if (exists) {
        [views addObject:[self treeBadge:@"已存在"]];
        if (url) {
            [views addObject:[self trashButtonForURL:url name:person isExtra:NO]];
        }
    }
    [views addObject:[self gapView]];
    return [self rowWithViews:views];
}

- (NSView *)treeOriginalRow:(NSString *)name
                  connector:(NSString *)connector
                   existing:(BOOL)exists
                       plan:(ArchivePlan *)plan {
    NSMutableArray *views = [NSMutableArray array];
    [views addObject:[self fixedSpacer:(plan.flatMode ? 18 : 36)]];
    [views addObject:[self treeConnectorLabel:connector]];
    if (plan.flatMode) {
        [views addObject:[self label:[plan baseName]
                                font:[NSFont systemFontOfSize:11.5]
                               color:[NSColor tertiaryLabelColor]]];
    }
    [views addObject:[self label:[name stringByAppendingString:@"/"]
                            font:[NSFont systemFontOfSize:12.5 weight:NSFontWeightMedium]
                           color:[NSColor labelColor]]];
    [views addObject:[self treeBadge:@"自动"]];
    if (exists) {
        [views addObject:[self trashButtonForURL:[plan directoryURLForFolderName:name]
                                            name:name
                                        isExtra:NO]];
    }
    [views addObject:[self gapView]];
    return [self rowWithViews:views];
}

- (NSButton *)trashButtonForURL:(NSURL *)url name:(NSString *)name isExtra:(BOOL)isExtra {
    NSImage *image = [NSImage imageWithSystemSymbolName:@"trash" accessibilityDescription:@"移到废纸篓"];
    image = [image imageWithSymbolConfiguration:
             [NSImageSymbolConfiguration configurationWithPointSize:11 weight:NSFontWeightMedium]];
    FolderTrashButton *button = [FolderTrashButton buttonWithImage:image
                                                            target:self
                                                            action:@selector(confirmDeleteFolder:)];
    button.bordered = NO;
    button.imagePosition = NSImageOnly;
    button.contentTintColor = [NSColor tertiaryLabelColor];
    button.toolTip = [NSString stringWithFormat:@"删除「%@」（移到废纸篓）", name];
    button.folderURL = url;
    button.folderName = name;
    button.isExtraFolder = isExtra;
    button.translatesAutoresizingMaskIntoConstraints = NO;
    [button.widthAnchor constraintEqualToConstant:20].active = YES;
    [button.heightAnchor constraintEqualToConstant:20].active = YES;
    return button;
}

- (NSInteger)fileCountInDirectory:(NSString *)path {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSDirectoryEnumerator *enumerator = [fm enumeratorAtPath:path];
    NSInteger count = 0;
    for (NSString *relative in enumerator) {
        BOOL isDir = NO;
        NSString *full = [path stringByAppendingPathComponent:relative];
        if ([fm fileExistsAtPath:full isDirectory:&isDir] && !isDir) count++;
    }
    return count;
}

- (void)confirmDeleteFolder:(FolderTrashButton *)sender {
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:sender.folderURL.path isDirectory:&isDir] || !isDir) {
        [self refreshPreview];
        return;
    }

    NSInteger fileCount = [self fileCountInDirectory:sender.folderURL.path];
    NSAlert *alert = [NSAlert new];
    alert.alertStyle = NSAlertStyleCritical;
    alert.messageText = @"删除文件夹？";
    alert.informativeText = [NSString stringWithFormat:
        @"「%@」以及里面的 %ld 个文件都会被移到废纸篓。\n\n%@\n\n可以稍后从废纸篓恢复。",
        sender.folderName, (long)fileCount, AbbreviatePath(sender.folderURL.path)];
    NSButton *deleteButton = [alert addButtonWithTitle:@"移到废纸篓"];
    deleteButton.hasDestructiveAction = YES;
    [alert addButtonWithTitle:@"取消"];

    [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
        if (response != NSAlertFirstButtonReturn) return;
        [self trashFolderAtURL:sender.folderURL
                       isExtra:sender.isExtraFolder
                          name:sender.folderName];
    }];
}

- (void)trashFolderAtURL:(NSURL *)url isExtra:(BOOL)isExtra name:(NSString *)name {
    NSError *error = nil;
    NSURL *trashedURL = nil;
    if (![[NSFileManager defaultManager] trashItemAtURL:url
                                      resultingItemURL:&trashedURL
                                                 error:&error]) {
        ShowError(self.window, @"无法移到废纸篓", error.localizedDescription ?: @"未知错误");
        return;
    }

    [[NSUserDefaults standardUserDefaults] removeObjectForKey:EventModeKey(url.path)];

    if (isExtra) {
        NSMutableArray<NSString *> *names = [[self selectedSubfolders] mutableCopy];
        [names removeObject:name];
        [self setSelectedSubfolders:names];
    } else {
        [self refreshPreview];
    }
    [self setStatus:[NSString stringWithFormat:@"✓ 已移到废纸篓：%@", name]];
}

- (NSView *)treeSubfolderRow:(NSString *)name
                       index:(NSUInteger)index
                   connector:(NSString *)connector
                    existing:(BOOL)exists
                        plan:(ArchivePlan *)plan {
    NSMutableArray *views = [NSMutableArray array];
    [views addObject:[self fixedSpacer:(plan.flatMode ? 18 : 36)]];
    [views addObject:[self treeConnectorLabel:connector]];

    if (plan.flatMode) {
        [views addObject:[self label:[plan baseName]
                                font:[NSFont systemFontOfSize:11.5]
                               color:[NSColor tertiaryLabelColor]]];
    }

    NSTextField *field = [NSTextField textFieldWithString:name];
    field.font = [NSFont systemFontOfSize:12.5];
    field.bezelStyle = NSTextFieldRoundedBezel;
    field.tag = 1000 + (NSInteger)index;
    field.target = self;
    field.action = @selector(treeFieldCommitted:);
    field.delegate = self;
    field.translatesAutoresizingMaskIntoConstraints = NO;
    CGFloat fieldWidth = MAX(110.0, MIN(320.0, field.intrinsicContentSize.width + 6.0));
    [field.widthAnchor constraintEqualToConstant:fieldWidth].active = YES;
    [views addObject:field];

    if (exists) {
        [views addObject:[self treeBadge:@"已存在"]];
        [views addObject:[self trashButtonForURL:[plan directoryURLForFolderName:name]
                                            name:name
                                        isExtra:YES]];
    }
    [views addObject:[self gapView]];
    return [self rowWithViews:views];
}

- (NSView *)treeAddRowForPlan:(ArchivePlan *)plan {
    NSButton *add = [NSButton buttonWithTitle:@"＋ 添加子文件夹"
                                      target:self
                                      action:@selector(addTreeSubfolder:)];
    add.bordered = NO;
    add.font = [NSFont systemFontOfSize:12];
    add.contentTintColor = [NSColor controlAccentColor];
    add.translatesAutoresizingMaskIntoConstraints = NO;
    CGFloat indent = plan.flatMode ? 48 : 66;
    return [self rowWithViews:@[ [self fixedSpacer:indent], add, [self gapView] ]];
}

- (void)addTreeSubfolder:(id)sender {
    if (self.pendingNewField) {
        [self.window makeFirstResponder:self.pendingNewField];
        return;
    }
    ArchivePlan *plan = [self currentPlan];
    NSMutableArray *views = [NSMutableArray array];
    [views addObject:[self fixedSpacer:(plan.flatMode ? 18 : 36)]];
    [views addObject:[self treeConnectorLabel:@"└──"]];
    if (plan.flatMode) {
        [views addObject:[self label:[plan baseName]
                                font:[NSFont systemFontOfSize:11.5]
                               color:[NSColor tertiaryLabelColor]]];
    }
    NSTextField *field = [NSTextField textFieldWithString:@""];
    field.font = [NSFont systemFontOfSize:12.5];
    field.bezelStyle = NSTextFieldRoundedBezel;
    field.placeholderString = @"新子文件夹名称";
    field.tag = 9999;
    field.target = self;
    field.action = @selector(treeFieldCommitted:);
    field.delegate = self;
    field.translatesAutoresizingMaskIntoConstraints = NO;
    [field.widthAnchor constraintGreaterThanOrEqualToConstant:180].active = YES;
    [field setContentHuggingPriority:1 forOrientation:NSLayoutConstraintOrientationHorizontal];
    [views addObject:field];
    [views addObject:[self gapView]];

    NSView *row = [self rowWithViews:views];
    NSUInteger index = self.treeStack.arrangedSubviews.count;
    [self.treeStack insertArrangedSubview:row atIndex:(index ? index - 1 : 0)];
    [row.widthAnchor constraintEqualToAnchor:self.treeStack.widthAnchor].active = YES;
    self.pendingNewField = field;
    [self.window makeFirstResponder:field];
}

- (void)treeFieldCommitted:(NSTextField *)field {
    if (self.committingTreeField) return;
    self.committingTreeField = YES;
    if (field.tag == 9999) {
        [self commitNewTreeSubfolder:field];
    } else {
        [self commitTreeRename:field];
    }
    self.committingTreeField = NO;
}

- (void)commitTreeRename:(NSTextField *)field {
    NSArray<NSString *> *names = [self selectedSubfolders];
    NSInteger index = field.tag - 1000;
    if (index < 0 || index >= (NSInteger)names.count) return;

    NSString *oldName = names[index];
    NSString *newName = SanitizeComponent(field.stringValue);
    if (!newName.length || [newName isEqualToString:oldName]) {
        field.stringValue = oldName;
        return;
    }
    if ([names containsObject:newName]) {
        NSBeep();
        field.stringValue = oldName;
        [self setStatus:[NSString stringWithFormat:@"「%@」已经在列表里了", newName]];
        return;
    }

    ArchivePlan *plan = [self currentPlan];
    NSURL *oldURL = [self subfolderURLForName:oldName plan:plan];
    NSURL *newURL = [self subfolderURLForName:newName plan:plan];
    NSString *errorMessage = nil;
    if (!SafeRenameDirectory(oldURL, newURL, &errorMessage)) {
        ShowError(self.window, @"无法重命名", errorMessage);
        field.stringValue = oldName;
        return;
    }

    BOOL existed = [[NSFileManager defaultManager] fileExistsAtPath:newURL.path];
    NSMutableArray *updated = [names mutableCopy];
    updated[index] = newName;
    self.subsTokenField.objectValue = [self sanitizedSubfolderNames:updated];
    dispatch_async(dispatch_get_main_queue(), ^{
        [self refreshPreview];
    });
    [self setStatus:(existed
        ? [NSString stringWithFormat:@"✓ 已重命名 %@ → %@", oldName, newName]
        : [NSString stringWithFormat:@"已更新计划：%@ → %@", oldName, newName])];
}

- (void)commitNewTreeSubfolder:(NSTextField *)field {
    if (self.pendingNewField != field) return;

    NSArray<NSString *> *names = [self selectedSubfolders];
    NSString *newName = SanitizeComponent(field.stringValue);
    if (!newName.length) {
        NSView *row = field.superview;
        self.pendingNewField = nil;
        if (row) {
            [self.treeStack removeArrangedSubview:row];
            [row removeFromSuperview];
        }
        return;
    }
    if ([names containsObject:newName]) {
        NSBeep();
        field.stringValue = @"";
        [self setStatus:[NSString stringWithFormat:@"「%@」已经在列表里了", newName]];
        return;
    }

    ArchivePlan *plan = [self currentPlan];
    BOOL created = NO;
    if (!plan.flatMode) {
        NSURL *eventURL = [self eventFolderURLForPlan:plan];
        if ([[NSFileManager defaultManager] fileExistsAtPath:eventURL.path]) {
            NSURL *target = [eventURL URLByAppendingPathComponent:newName isDirectory:YES];
            NSError *error = nil;
            if (![[NSFileManager defaultManager] createDirectoryAtURL:target
                                             withIntermediateDirectories:YES
                                                              attributes:nil
                                                                   error:&error]) {
                ShowError(self.window, @"无法新建子文件夹", error.localizedDescription);
                return;
            }
            created = YES;
        }
    }

    self.pendingNewField = nil;
    NSArray *updated = [names arrayByAddingObject:newName];
    self.subsTokenField.objectValue = [self sanitizedSubfolderNames:updated];
    dispatch_async(dispatch_get_main_queue(), ^{
        [self refreshPreview];
    });
    [self setStatus:(created
        ? [NSString stringWithFormat:@"✓ 已新建子文件夹「%@」", newName]
        : [NSString stringWithFormat:@"已加入计划：「%@」会在创建时一并建立", newName])];
}

- (NSArray<NSString *> *)subfolderNamesInDirectory:(NSString *)path {
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    NSMutableArray *names = [NSMutableArray array];
    if (path.length && [fm fileExistsAtPath:path isDirectory:&isDir] && isDir) {
        NSArray *items = [fm contentsOfDirectoryAtPath:path error:NULL] ?: @[];
        items = [items sortedArrayUsingSelector:@selector(localizedStandardCompare:)];
        for (NSString *name in items) {
            if ([name hasPrefix:@"."]) continue;
            BOOL subIsDir = NO;
            if ([fm fileExistsAtPath:[path stringByAppendingPathComponent:name]
                         isDirectory:&subIsDir] && subIsDir) {
                [names addObject:name];
            }
        }
    }
    return names;
}

#pragma mark 子文件夹标签

- (NSArray<NSString *> *)selectedSubfolders {
    id value = self.subsTokenField.objectValue;
    NSMutableArray *names = [NSMutableArray array];
    if ([value isKindOfClass:[NSArray class]]) {
        for (id token in value) {
            NSString *raw = [token isKindOfClass:[NSString class]] ? token : [token description];
            NSString *name = SanitizeComponent(raw);
            if (name.length && ![names containsObject:name]) [names addObject:name];
        }
    } else if ([value isKindOfClass:[NSString class]]) {
        for (NSString *name in ParseSubfolders(value)) {
            if (![names containsObject:name]) [names addObject:name];
        }
    }
    return names;
}

- (NSArray<NSString *> *)sanitizedSubfolderNames:(NSArray *)names {
    NSMutableArray *clean = [NSMutableArray array];
    for (NSString *name in names) {
        NSString *value = SanitizeComponent([name description]);
        if (value.length && ![clean containsObject:value]) [clean addObject:value];
    }
    return clean;
}

- (void)setSelectedSubfolders:(NSArray<NSString *> *)names {
    self.subsTokenField.objectValue = [self sanitizedSubfolderNames:names];
    [self refreshPreview];
}

- (void)loadSubfolderRecents {
    NSString *json = [[NSUserDefaults standardUserDefaults] stringForKey:kKeySubRecents];
    NSArray *entries = @[];
    if (json.length) {
        id object = [NSJSONSerialization JSONObjectWithData:[json dataUsingEncoding:NSUTF8StringEncoding]
                                                    options:0 error:NULL];
        if ([object isKindOfClass:[NSArray class]]) entries = object;
    }
    self.subfolderRecents = entries;
}

- (void)clearRecentSubfolders:(id)sender {
    self.subfolderRecents = @[];
    [self persistSubfolderRecents];
    [self setStatus:@"✓ 已清空最近常用历史"];
}

- (void)persistSubfolderRecents {
    NSData *data = [NSJSONSerialization dataWithJSONObject:self.subfolderRecents options:0 error:NULL];
    NSString *json = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : @"[]";
    [[NSUserDefaults standardUserDefaults] setObject:(json ?: @"[]") forKey:kKeySubRecents];
}

- (void)recordSubfolderUsage:(NSArray<NSString *> *)names {
    if (!names.count) return;
    NSMutableArray<NSMutableDictionary *> *recents = [NSMutableArray array];
    for (NSDictionary *entry in self.subfolderRecents) {
        if ([entry isKindOfClass:[NSDictionary class]]) [recents addObject:[entry mutableCopy]];
    }
    NSDate *now = [NSDate date];
    for (NSString *name in names) {
        NSInteger index = -1;
        for (NSUInteger i = 0; i < recents.count; i++) {
            if ([recents[i][@"name"] isEqualToString:name]) { index = (NSInteger)i; break; }
        }
        if (index >= 0) {
            recents[index][@"count"] = @([recents[index][@"count"] integerValue] + 1);
            recents[index][@"last"] = @([now timeIntervalSince1970]);
        } else {
            [recents addObject:[@{ @"name": name,
                                  @"count": @1,
                                  @"last": @([now timeIntervalSince1970]) } mutableCopy]];
        }
    }
    [recents sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        NSInteger ca = [a[@"count"] integerValue];
        NSInteger cb = [b[@"count"] integerValue];
        if (ca != cb) return ca > cb ? NSOrderedAscending : NSOrderedDescending;
        return [b[@"last"] compare:a[@"last"]];
    }];
    if (recents.count > 16) [recents removeObjectsInRange:NSMakeRange(16, recents.count - 16)];
    self.subfolderRecents = recents;
    [self persistSubfolderRecents];
}

- (NSArray<NSString *> *)recentSubfolderNamesExcluding:(NSArray<NSString *> *)excluded {
    NSMutableArray *names = [NSMutableArray array];
    for (NSDictionary *entry in self.subfolderRecents) {
        NSString *name = entry[@"name"];
        if (![name isKindOfClass:[NSString class]] || !name.length) continue;
        if ([name isEqualToString:kOriginalPhotoName] ||
            [name isEqualToString:kOriginalVideoName] ||
            [name isEqualToString:@"（原始）"]) continue;
        if ([excluded containsObject:name] || [names containsObject:name]) continue;
        [names addObject:name];
        if (names.count >= 8) break;
    }
    return names;
}

- (void)showSubfolderMenu:(NSButton *)sender {
    NSArray<NSString *> *selected = [self selectedSubfolders];
    NSMenu *menu = [[NSMenu alloc] initWithTitle:@"子文件夹"];
    [menu setAutoenablesItems:NO];

    NSMenuItem *presetHeader = [[NSMenuItem alloc] initWithTitle:@"预设" action:nil keyEquivalent:@""];
    presetHeader.enabled = NO;
    [menu addItem:presetHeader];
    for (NSString *name in SubfolderPresets()) {
        NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:name
                                                     action:@selector(toggleSubfolderFromMenu:)
                                              keyEquivalent:@""];
        item.target = self;
        item.representedObject = name;
        item.state = [selected containsObject:name] ? NSControlStateValueOn : NSControlStateValueOff;
        [menu addItem:item];
    }

    NSArray<NSString *> *recents = [self recentSubfolderNamesExcluding:SubfolderPresets()];
    [menu addItem:[NSMenuItem separatorItem]];
    NSMenuItem *recentHeader = [[NSMenuItem alloc] initWithTitle:@"最近常用" action:nil keyEquivalent:@""];
    recentHeader.enabled = NO;
    [menu addItem:recentHeader];
    if (recents.count) {
        for (NSString *name in recents) {
            NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:name
                                                         action:@selector(toggleSubfolderFromMenu:)
                                                  keyEquivalent:@""];
            item.target = self;
            item.representedObject = name;
            item.state = [selected containsObject:name] ? NSControlStateValueOn : NSControlStateValueOff;
            [menu addItem:item];
        }
    } else {
        NSMenuItem *empty = [[NSMenuItem alloc] initWithTitle:@"（创建后会记录到这里）" action:nil keyEquivalent:@""];
        empty.enabled = NO;
        [menu addItem:empty];
    }

    [menu addItem:[NSMenuItem separatorItem]];
    NSMenuItem *clearRecents = [[NSMenuItem alloc] initWithTitle:@"清空最近常用历史"
                                                          action:@selector(clearRecentSubfolders:)
                                                   keyEquivalent:@""];
    clearRecents.target = self;
    clearRecents.enabled = self.subfolderRecents.count > 0;
    [menu addItem:clearRecents];

    [menu popUpMenuPositioningItem:nil
                        atLocation:NSMakePoint(0, sender.bounds.size.height + 4)
                            inView:sender];
}

- (void)toggleSubfolderFromMenu:(NSMenuItem *)item {
    NSString *name = item.representedObject;
    if (![name isKindOfClass:[NSString class]] || !name.length) return;
    NSMutableArray *selected = [[self selectedSubfolders] mutableCopy];
    if ([selected containsObject:name]) {
        [selected removeObject:name];
    } else {
        [selected addObject:name];
    }
    [self setSelectedSubfolders:selected];
}

- (NSArray *)tokenField:(NSTokenField *)tokenField
completionsForSubstring:(NSString *)substring
           indexOfToken:(NSInteger)tokenIndex
    indexOfSelectedItem:(NSInteger *)selectedIndex {
    NSMutableArray *candidates = [NSMutableArray arrayWithArray:SubfolderPresets()];
    [candidates addObjectsFromArray:[self recentSubfolderNamesExcluding:SubfolderPresets()]];
    NSMutableArray *matches = [NSMutableArray array];
    for (NSString *name in candidates) {
        if (!substring.length || [name containsString:substring]) [matches addObject:name];
    }
    return matches;
}

- (void)controlTextDidEndEditing:(NSNotification *)note {
    if ([note.object isKindOfClass:[NSTextField class]]) {
        NSTextField *field = note.object;
        if (field.tag >= 1000) {
            [self treeFieldCommitted:field];
            return;
        }
    }
    [self refreshPreview];
}


#pragma mark 署名规则

- (void)loadSignRules {
    NSString *json = [[NSUserDefaults standardUserDefaults] stringForKey:kKeySignRules];
    NSArray *rules = @[];
    if (json.length) {
        NSData *data = [json dataUsingEncoding:NSUTF8StringEncoding];
        id object = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
        if ([object isKindOfClass:[NSArray class]]) rules = object;
    }
    self.signRules = rules;
}

- (void)persistSignRules:(NSArray<NSDictionary *> *)rules {
    NSData *data = [NSJSONSerialization dataWithJSONObject:rules options:0 error:NULL];
    NSString *json = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    [[NSUserDefaults standardUserDefaults] setObject:(json ?: @"[]") forKey:kKeySignRules];
    self.signRules = rules;
}

- (void)buildRulesWindow {
    NSWindow *w = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 580, 460)
                                              styleMask:NSWindowStyleMaskTitled
                                                backing:NSBackingStoreBuffered
                                                  defer:NO];
    w.title = @"署名规则";

    NSView *content = w.contentView;
    NSStackView *root = [NSStackView new];
    root.orientation = NSUserInterfaceLayoutOrientationVertical;
    root.alignment = NSLayoutAttributeLeading;
    root.spacing = 10;
    root.translatesAutoresizingMaskIntoConstraints = NO;
    [content addSubview:root];
    [NSLayoutConstraint activateConstraints:@[
        [root.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:22],
        [root.trailingAnchor constraintEqualToAnchor:content.trailingAnchor constant:-22],
        [root.topAnchor constraintEqualToAnchor:content.topAnchor constant:18],
        [root.bottomAnchor constraintEqualToAnchor:content.bottomAnchor constant:-18],
    ]];

    NSTextField *title = [self label:@"自动署名规则"
                                font:[NSFont systemFontOfSize:14 weight:NSFontWeightSemibold]
                               color:[NSColor labelColor]];
    [root addArrangedSubview:title];

    NSTextField *hint = [self label:@"读取照片时，如果作者、相机型号或机身/镜头序列号命中关键词，就自动勾选署名并填入右边的文字。不区分大小写。"
                               font:[NSFont systemFontOfSize:11.5]
                              color:[NSColor secondaryLabelColor]];
    hint.maximumNumberOfLines = 3;
    hint.lineBreakMode = NSLineBreakByWordWrapping;
    [root addArrangedSubview:hint];
    [hint.widthAnchor constraintEqualToAnchor:root.widthAnchor].active = YES;

    self.unknownFolderInferenceCheck = [NSButton checkboxWithTitle:@"根据上级文件夹分类未标注文件"
                                                            target:self
                                                            action:@selector(unknownFolderInferenceToggled:)];
    self.unknownFolderInferenceCheck.state = NSControlStateValueOn;
    self.unknownFolderInferenceCheck.font = [NSFont systemFontOfSize:11.5];
    self.unknownFolderInferenceCheck.toolTip = @"文件夹里只有一位作者时，把同文件夹里没有信息的文件归给他；保存后会列出文件名确认";
    [root addArrangedSubview:self.unknownFolderInferenceCheck];

    NSTextField *applyHint = [self label:@"点「保存并应用」后才会按文件夹归类并弹出确认；点「取消导入」会放弃这一批素材，不改动目录。"
                                   font:[NSFont systemFontOfSize:10.5]
                                  color:[NSColor tertiaryLabelColor]];
    applyHint.maximumNumberOfLines = 2;
    applyHint.lineBreakMode = NSLineBreakByWordWrapping;
    [root addArrangedSubview:applyHint];
    [applyHint.widthAnchor constraintEqualToAnchor:root.widthAnchor].active = YES;

    NSScrollView *scroll = [[NSScrollView alloc] init];
    scroll.translatesAutoresizingMaskIntoConstraints = NO;
    scroll.hasVerticalScroller = YES;
    scroll.autohidesScrollers = YES;
    scroll.borderType = NSNoBorder;
    scroll.drawsBackground = YES;
    scroll.backgroundColor = [NSColor controlBackgroundColor];
    scroll.wantsLayer = YES;
    scroll.layer.cornerRadius = 8;
    scroll.layer.borderWidth = 1;
    scroll.layer.borderColor = [NSColor separatorColor].CGColor;
    [scroll.heightAnchor constraintEqualToConstant:236].active = YES;

    self.rulesStackView = [FlippedStackView new];
    self.rulesStackView.orientation = NSUserInterfaceLayoutOrientationVertical;
    self.rulesStackView.alignment = NSLayoutAttributeLeading;
    self.rulesStackView.spacing = 8;
    self.rulesStackView.translatesAutoresizingMaskIntoConstraints = NO;
    scroll.documentView = self.rulesStackView;
    [NSLayoutConstraint activateConstraints:@[
        [self.rulesStackView.leadingAnchor constraintEqualToAnchor:scroll.contentView.leadingAnchor constant:10],
        [self.rulesStackView.trailingAnchor constraintEqualToAnchor:scroll.contentView.trailingAnchor constant:-10],
        [self.rulesStackView.topAnchor constraintEqualToAnchor:scroll.contentView.topAnchor constant:10],
    ]];
    [root addArrangedSubview:scroll];
    [scroll.widthAnchor constraintEqualToAnchor:root.widthAnchor].active = YES;

    NSView *gap = [self gapView];
    NSButton *add = [self button:@"添加一条" action:@selector(addRuleRow:)];
    NSButton *done = [self button:@"完成" action:@selector(finishRules:)];
    done.keyEquivalent = @"\r";
    done.bezelColor = [NSColor controlAccentColor];
    NSStackView *footer = [self rowWithViews:@[ add, gap, done ]];
    [root addArrangedSubview:footer];
    [footer.widthAnchor constraintEqualToAnchor:root.widthAnchor].active = YES;

    self.rulesWindow = w;
}

- (void)showRules:(id)sender {
    if (!self.rulesWindow) [self buildRulesWindow];
    [self reloadRulesRows];
    [self.window beginSheet:self.rulesWindow completionHandler:nil];
}

- (void)reloadRulesRows {
    for (NSView *view in [self.rulesStackView.arrangedSubviews copy]) {
        [self.rulesStackView removeArrangedSubview:view];
        [view removeFromSuperview];
    }
    if (!self.signRules.count) {
        [self addRuleRowWithKeyword:@"" signature:@""];
    } else {
        for (NSDictionary *rule in self.signRules) {
            [self addRuleRowWithKeyword:rule[@"keyword"] ?: @"" signature:rule[@"signature"] ?: @""];
        }
    }
}

- (NSView *)ruleRowWithKeyword:(NSString *)keyword signature:(NSString *)signature {
    NSTextField *keywordField = [NSTextField textFieldWithString:keyword ?: @""];
    keywordField.translatesAutoresizingMaskIntoConstraints = NO;
    keywordField.placeholderString = @"作者 / 相机型号 / 机身序列号";
    keywordField.font = [NSFont systemFontOfSize:12.5];
    [keywordField setContentHuggingPriority:1 forOrientation:NSLayoutConstraintOrientationHorizontal];
    [keywordField.widthAnchor constraintGreaterThanOrEqualToConstant:160].active = YES;

    NSTextField *arrow = [self label:@"→"
                                font:[NSFont systemFontOfSize:12]
                               color:[NSColor tertiaryLabelColor]];

    NSTextField *signatureField = [NSTextField textFieldWithString:signature ?: @""];
    signatureField.translatesAutoresizingMaskIntoConstraints = NO;
    signatureField.placeholderString = @"署名，如：张三";
    signatureField.font = [NSFont systemFontOfSize:12.5];
    [signatureField setContentHuggingPriority:1 forOrientation:NSLayoutConstraintOrientationHorizontal];
    [signatureField.widthAnchor constraintGreaterThanOrEqualToConstant:130].active = YES;

    NSButton *remove = [NSButton buttonWithTitle:@"−" target:self action:@selector(removeRuleRow:)];
    remove.bezelStyle = NSBezelStyleRounded;
    remove.translatesAutoresizingMaskIntoConstraints = NO;
    [remove.widthAnchor constraintEqualToConstant:28].active = YES;

    NSStackView *row = [self rowWithViews:@[ keywordField, arrow, signatureField, remove ]];
    return row;
}

- (void)addRuleRowWithKeyword:(NSString *)keyword signature:(NSString *)signature {
    NSView *row = [self ruleRowWithKeyword:keyword signature:signature];
    [self.rulesStackView addArrangedSubview:row];
    [row.widthAnchor constraintEqualToAnchor:self.rulesStackView.widthAnchor].active = YES;
}

- (void)addRuleRow:(id)sender {
    [self addRuleRowWithKeyword:@"" signature:@""];
    NSView *last = self.rulesStackView.arrangedSubviews.lastObject;
    [self.rulesWindow makeFirstResponder:[[last subviews] firstObject]];
}

- (void)removeRuleRow:(NSButton *)sender {
    NSView *row = sender.superview;
    if (!row) return;
    [self.rulesStackView removeArrangedSubview:row];
    [row removeFromSuperview];
    if (!self.rulesStackView.arrangedSubviews.count) {
        [self addRuleRowWithKeyword:@"" signature:@""];
    }
}

- (void)collectRules {
    NSMutableArray *rules = [NSMutableArray array];
    for (NSView *view in self.rulesStackView.arrangedSubviews) {
        if (![view isKindOfClass:[NSStackView class]]) continue;
        NSStackView *row = (NSStackView *)view;
        if (row.arrangedSubviews.count < 3) continue;
        NSTextField *keywordField = (NSTextField *)row.arrangedSubviews[0];
        NSTextField *signatureField = (NSTextField *)row.arrangedSubviews[2];
        if (![keywordField isKindOfClass:[NSTextField class]] ||
            ![signatureField isKindOfClass:[NSTextField class]]) continue;
        NSString *keyword = Trim(keywordField.stringValue);
        NSString *signature = Trim(signatureField.stringValue);
        if (keyword.length && signature.length) {
            [rules addObject:@{ @"keyword": keyword, @"signature": signature }];
        }
    }
    [self persistSignRules:rules];
}

- (void)finishRules:(id)sender {
    [self collectRules];
    [self.window endSheet:self.rulesWindow];
    [self.rulesWindow orderOut:nil];
    [self computeDerivedSignatureState];
    [self setStatus:@"署名规则已保存"];
}

/// 按规则把照片信息映射成署名；未启用自动署名时返回 nil。
- (NSString *)mappedSignatureForItem:(MediaItem *)item {
    if (self.autoSignCheck.state != NSControlStateValueOn) return nil;
    NSArray<NSString *> *values = [item.meta identityValues];
    for (NSDictionary *rule in self.signRules) {
        NSString *keyword = Trim(rule[@"keyword"] ?: @"");
        NSString *signature = Trim(rule[@"signature"] ?: @"");
        if (!keyword.length || !signature.length) continue;
        for (NSString *value in values) {
            if (ValueMatchesKeyword(value, keyword)) return signature;
        }
    }
    if (!values.count) {
        NSString *folderName = item.url.URLByDeletingLastPathComponent.lastPathComponent;
        if (folderName.length) {
            for (NSDictionary *rule in self.signRules) {
                NSString *keyword = Trim(rule[@"keyword"] ?: @"");
                NSString *signature = Trim(rule[@"signature"] ?: @"");
                if (keyword.length && signature.length &&
                    [folderName caseInsensitiveCompare:keyword] == NSOrderedSame) {
                    return signature;
                }
            }
        }
        for (NSDictionary *rule in self.signRules) {
            NSString *keyword = Trim(rule[@"keyword"] ?: @"");
            NSString *signature = Trim(rule[@"signature"] ?: @"");
            if ([keyword isEqualToString:kUnknownAuthorName] && signature.length) {
                return signature;
            }
        }
    }
    for (NSString *value in values) {
        NSString *signature = self.batchSignatureMappings[value];
        if (signature.length) return signature;
    }
    if (!values.count) {
        NSString *fallback = self.batchSignatureMappings[kUnknownAuthorName];
        if (fallback.length) return fallback;
    }
    return nil;
}

/// 人名：优先规则映射的署名，其次用原始作者。
- (NSString *)personNameForItem:(MediaItem *)item {
    if (self.multiPerson && ![item.meta identityValues].count) {
        NSString *folderPath = item.url.URLByDeletingLastPathComponent.path;
        NSString *folderName = self.batchFolderPersonMappings[folderPath];
        if (folderName.length) return SanitizeComponent(folderName);
    }
    NSString *mapped = [self mappedSignatureForItem:item];
    if (mapped.length) return mapped;
    return SanitizeComponent(item.meta.artist ?: @"");
}

/// 重新计算人名列表（多人模式的目录）和单人模式的自动署名。
- (void)computeDerivedSignatureState {
    NSArray<MediaItem *> *items = self.items ?: @[];
    NSMutableArray<NSString *> *rawAuthors = [NSMutableArray array];
    NSMutableArray<NSString *> *photoPersons = [NSMutableArray array];
    NSMutableArray<NSString *> *videoPersons = [NSMutableArray array];
    NSMutableDictionary<NSString *, NSNumber *> *counts = [NSMutableDictionary dictionary];
    BOOL photoWithoutPerson = NO;
    BOOL videoWithoutPerson = NO;

    for (MediaItem *item in items) {
        NSString *rawAuthor = SanitizeComponent(item.meta.artist ?: @"");
        if (rawAuthor.length && ![rawAuthors containsObject:rawAuthor]) {
            [rawAuthors addObject:rawAuthor];
        }
        BOOL isVideo = item.previewFile ||
                       [MovieExtensions() containsObject:item.url.pathExtension.lowercaseString] ||
                       [AudioExtensions() containsObject:item.url.pathExtension.lowercaseString];
        NSString *person = [self personNameForItem:item];
        if (isVideo) {
            if (person.length) {
                if (![videoPersons containsObject:person]) [videoPersons addObject:person];
            } else if (self.multiPerson) {
                videoWithoutPerson = YES;
            }
        } else if (person.length) {
            if (![photoPersons containsObject:person]) [photoPersons addObject:person];
        } else if (self.multiPerson) {
            photoWithoutPerson = YES;
        }
        NSString *mapped = [self mappedSignatureForItem:item];
        if (mapped.length) counts[mapped] = @(counts[mapped].integerValue + 1);
    }
    if (photoWithoutPerson && ![photoPersons containsObject:kUnknownAuthorName]) {
        [photoPersons addObject:kUnknownAuthorName];
    }
    if (videoWithoutPerson && ![videoPersons containsObject:kUnknownAuthorName]) {
        [videoPersons addObject:kUnknownAuthorName];
    }

    self.detectedPhotoAuthors = photoPersons;
    self.detectedVideoAuthors = videoPersons;

    NSMutableArray *allPersons = [photoPersons mutableCopy];
    for (NSString *name in videoPersons) {
        if (![allPersons containsObject:name]) [allPersons addObject:name];
    }
    self.detectedAuthors = allPersons;

    NSString *best = nil;
    NSInteger bestCount = 0;
    for (NSString *key in counts) {
        NSInteger count = counts[key].integerValue;
        if (count > bestCount) {
            best = key;
            bestCount = count;
        }
    }
    self.autoSignature = best;
    self.detectedRawAuthors = rawAuthors;
    [self refreshAutoSignatureStatus];
    [self refreshPreview];
}

- (void)refreshAutoSignatureStatus {
    if (!self.autoSignStatusView) return;

    NSString *text = @"";
    NSString *tip = @"";
    NSColor *color = [NSColor colorWithSRGBRed:0.42 green:0.42 blue:0.44 alpha:1.0];

    if (self.multiPerson) {
        text = @"用于人名";
        tip = @"多人模式下，自动署名用于原始照片 / 视频里的人名文件夹";
    } else if (self.autoSignCheck.state != NSControlStateValueOn) {
        text = @"已关闭";
        tip = @"自动署名未开启";
    } else if (self.signCheck.state == NSControlStateValueOn &&
               Trim(self.signField.stringValue).length) {
        text = @"手动优先";
        tip = [NSString stringWithFormat:@"手动署名「%@」已生效，自动署名不会应用到最外层文件夹。",
               Trim(self.signField.stringValue)];
        color = [NSColor colorWithSRGBRed:0.82 green:0.16 blue:0.15 alpha:1.0];
    } else if (self.detectedRawAuthors.count > 1) {
        text = @"多位作者";
        tip = [NSString stringWithFormat:@"识别到 %lu 位作者：%@。单人模式下自动署名不可用，可切换多人模式。",
               (unsigned long)self.detectedRawAuthors.count,
               [self.detectedRawAuthors componentsJoinedByString:@"、"]];
        color = [NSColor systemRedColor];
    } else if (self.detectedRawAuthors.count == 0) {
        text = @"未识别";
        tip = @"还没有从照片里读到作者信息";
    } else if (!self.autoSignature.length) {
        text = @"缺少规则";
        tip = [NSString stringWithFormat:@"作者「%@」还没有对应的署名规则。",
               self.detectedRawAuthors.firstObject];
        color = [NSColor colorWithSRGBRed:0.82 green:0.16 blue:0.15 alpha:1.0];
    } else {
        text = self.autoSignature;
        tip = [NSString stringWithFormat:@"自动署名可用：%@", self.autoSignature];
        color = [NSColor colorWithSRGBRed:0.10 green:0.55 blue:0.25 alpha:1.0];
    }

    [self.autoSignStatusView setStatusText:text color:color tooltip:tip];
}

- (void)maybeShowSignatureConflict {
    [self presentSignatureConflictIfNeededWithCompletion:nil];
}

- (void)presentSignatureConflictIfNeededWithCompletion:(void (^)(void))completion {
    if (getenv("DSH_NO_ALERTS")) {
        if (completion) completion();
        return;
    }
    if (self.multiPerson) {
        if (completion) completion();
        return;
    }
    if (self.autoSignCheck.state != NSControlStateValueOn) {
        if (completion) completion();
        return;
    }
    if (self.signCheck.state != NSControlStateValueOn) {
        if (completion) completion();
        return;
    }
    NSString *manual = Trim(self.signField.stringValue);
    if (!manual.length || !self.autoSignature.length) {
        if (completion) completion();
        return;
    }
    if ([manual isEqualToString:self.autoSignature]) {
        if (completion) completion();
        return;
    }

    if (!self.conflictShownKeys) self.conflictShownKeys = [NSMutableSet set];
    NSString *key = [manual stringByAppendingFormat:@"|%@", self.autoSignature];
    if ([self.conflictShownKeys containsObject:key]) {
        if (completion) completion();
        return;
    }
    [self.conflictShownKeys addObject:key];

    NSAlert *alert = [NSAlert new];
    alert.messageText = @"手动署名优先";
    alert.informativeText = [NSString stringWithFormat:
        @"手动署名「%@」已生效，自动署名「%@」不会应用到最外层文件夹。\n如需使用自动署名，请取消勾选「手动署名」。",
        manual, self.autoSignature];
    alert.alertStyle = NSAlertStyleInformational;
    [alert addButtonWithTitle:@"好"];
    [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
        if (completion) completion();
    }];
}

- (NSView *)metadataTableRowWithValues:(NSArray<NSString *> *)values header:(BOOL)header {
    NSArray<NSNumber *> *widths = @[ @90, @210, @130 ];
    NSMutableArray<NSTextField *> *cells = [NSMutableArray array];
    for (NSUInteger i = 0; i < 4; i++) {
        NSString *text = (i < values.count) ? values[i] : @"";
        NSTextField *cell = [self label:text
                                   font:header ? [NSFont systemFontOfSize:11.5 weight:NSFontWeightSemibold]
                                              : [NSFont systemFontOfSize:12]
                                  color:header ? [NSColor secondaryLabelColor] : [NSColor labelColor]];
        cell.lineBreakMode = NSLineBreakByTruncatingTail;
        cell.toolTip = text.length ? text : nil;
        if (i < 3) {
            [cell.widthAnchor constraintEqualToConstant:widths[i].doubleValue].active = YES;
        } else {
            [cell setContentHuggingPriority:1 forOrientation:NSLayoutConstraintOrientationHorizontal];
            [cell setContentCompressionResistancePriority:250
                                           forOrientation:NSLayoutConstraintOrientationHorizontal];
        }
        [cells addObject:cell];
    }
    NSStackView *row = [NSStackView stackViewWithViews:cells];
    row.orientation = NSUserInterfaceLayoutOrientationHorizontal;
    row.alignment = NSLayoutAttributeCenterY;
    row.spacing = 12;
    row.translatesAutoresizingMaskIntoConstraints = NO;
    return row;
}

- (void)updateMetaGridForItems:(NSArray<MediaItem *> *)items {
    for (NSView *view in [self.metaGrid.arrangedSubviews copy]) {
        [self.metaGrid removeArrangedSubview:view];
        [view removeFromSuperview];
    }

    NSMutableDictionary<NSString *, NSMutableArray<MediaItem *> *> *groups = [NSMutableDictionary dictionary];
    NSMutableArray<NSString *> *order = [NSMutableArray array];
    for (MediaItem *item in items) {
        NSString *person = [self personNameForItem:item];
        NSString *key = person.length ? person : @"";
        if (!groups[key]) {
            groups[key] = [NSMutableArray array];
            [order addObject:key];
        }
        [groups[key] addObject:item];
    }

    NSMutableArray<NSDictionary *> *rows = [NSMutableArray array];
    for (NSString *key in order) {
        NSArray<MediaItem *> *group = groups[key];
        NSString *cameras = JoinedTopValues(TopValues(group, ^NSString *(MediaItem *item) {
            if (item.meta.make.length && item.meta.model.length) {
                return [NSString stringWithFormat:@"%@ %@", item.meta.make, item.meta.model];
            }
            return item.meta.model.length ? item.meta.model : item.meta.make;
        }, 2));
        NSString *serials = JoinedTopValues(TopValues(group, ^NSString *(MediaItem *item) {
            return item.meta.bodySerial;
        }, 2));
        NSString *lenses = JoinedTopValues(TopValues(group, ^NSString *(MediaItem *item) {
            return item.meta.lens.length ? item.meta.lens : item.meta.lensSerial;
        }, 2));
        if (!key.length && !cameras.length && !serials.length && !lenses.length) continue;
        [rows addObject:@{ @"author": key, @"camera": cameras ?: @"",
                           @"serial": serials ?: @"", @"lens": lenses ?: @"",
                           @"count": @(group.count) }];
    }

    [rows sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        NSInteger ca = [a[@"count"] integerValue];
        NSInteger cb = [b[@"count"] integerValue];
        if (ca != cb) return ca > cb ? NSOrderedAscending : NSOrderedDescending;
        return [a[@"author"] localizedStandardCompare:b[@"author"]];
    }];

    self.metaGrid.hidden = (rows.count == 0);
    if (!rows.count) return;

    NSView *header = [self metadataTableRowWithValues:@[ @"作者", @"相机", @"机身序列号", @"镜头" ]
                                               header:YES];
    [self.metaGrid addArrangedSubview:header];
    [header.widthAnchor constraintEqualToAnchor:self.metaGrid.widthAnchor].active = YES;

    NSBox *separator = [[NSBox alloc] init];
    separator.boxType = NSBoxSeparator;
    separator.translatesAutoresizingMaskIntoConstraints = NO;
    [self.metaGrid addArrangedSubview:separator];
    [separator.widthAnchor constraintEqualToAnchor:self.metaGrid.widthAnchor].active = YES;
    [self.metaGrid setCustomSpacing:6 afterView:header];
    [self.metaGrid setCustomSpacing:4 afterView:separator];

    for (NSDictionary *row in rows) {
        NSView *rowView = [self metadataTableRowWithValues:@[ row[@"author"] ?: @"",
                                                             row[@"camera"] ?: @"",
                                                             row[@"serial"] ?: @"",
                                                             row[@"lens"] ?: @"" ]
                                                    header:NO];
        [self.metaGrid addArrangedSubview:rowView];
        [rowView.widthAnchor constraintEqualToAnchor:self.metaGrid.widthAnchor].active = YES;
    }
}


#pragma mark 关于

- (NSString *)appVersionString {
    NSString *version = [[NSBundle mainBundle] infoDictionary][@"CFBundleShortVersionString"];
    return version.length ? version : kAppVersion;
}

- (NSString *)bundledDocNamed:(NSString *)name {
    NSString *path = [[NSBundle mainBundle] pathForResource:name ofType:@"md"];
    if (path.length) {
        NSString *text = [NSString stringWithContentsOfFile:path
                                                    encoding:NSUTF8StringEncoding
                                                       error:NULL];
        if (text.length) return text;
    }
    return @"（文档未打包）";
}

- (void)showAbout:(id)sender {
    if (!self.aboutWindow) [self buildAboutWindow];
    self.aboutSegment.selectedSegment = 0;
    [self updateAboutContent];
    [self.aboutWindow makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
}

- (void)aboutTabChanged:(id)sender {
    [self updateAboutContent];
}

- (void)updateAboutContent {
    NSInteger index = self.aboutSegment.selectedSegment;
    NSString *text;
    if (index == 1) {
        text = [self bundledDocNamed:@"CHANGELOG"];
    } else if (index == 2) {
        text = [self bundledDocNamed:@"FEATURES"];
    } else {
        text = [NSString stringWithFormat:
            @"把散乱的素材，按「拍摄日期 + 事件名」整理成可以直接交付的标准目录。\n\n"
            @"### 核心能力\n"
            @"- 标准目录一次建好：原始照片 / 原始视频 / 自定义子文件夹，创建前实时预览\n"
            @"- 按 EXIF 拍摄时间自动归位；日期锁定，跨批导入不一致会提示\n"
            @"- 图片 / RAW / 视频 / 音频自动分流，文件类型和扩展名可以自己维护\n"
            @"- 单人模式完全扁平；多人模式按作者分层，增量导入自动合并\n"
            @"- 目录树里直接改名、加子文件夹；不需要的目录删到废纸篓，可恢复\n\n"
            @"### 特色\n"
            @"- 手动 / 自动署名与规则；未知身份先询问，无作者信息的素材按文件夹分组并可确认\n"
            @"- 来源标签可自定义，多人模式下并入人名文件夹\n"
            @"- 写入校验：xxHash64 / MD5；移动时先校验通过再删源文件\n"
            @"- 自动识别大疆等相机的低清预览文件，默认跳过，也可选择保留\n"
            @"- 事件目录创建后人员模式自动锁定，避免结构被改乱\n"
            @"- 全程本地运行，无第三方依赖\n\n"
            @"### 版本\n- 当前版本：%@\n- 开发者：%@\n",
            [self appVersionString], kDeveloper];
    }

    NSAttributedString *rendered = RenderMarkdownDocument(text);
    [self.aboutTextView.textStorage setAttributedString:rendered];
    [self.aboutTextView scrollRangeToVisible:NSMakeRange(0, 0)];
}

- (void)buildAboutWindow {
    NSWindow *w = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 640, 610)
                                              styleMask:(NSWindowStyleMaskTitled |
                                                         NSWindowStyleMaskClosable)
                                                backing:NSBackingStoreBuffered
                                                  defer:NO];
    w.title = @"关于 自动归档";
    w.releasedWhenClosed = NO;

    NSView *content = w.contentView;
    NSStackView *root = [NSStackView new];
    root.orientation = NSUserInterfaceLayoutOrientationVertical;
    root.alignment = NSLayoutAttributeLeading;
    root.spacing = 12;
    root.translatesAutoresizingMaskIntoConstraints = NO;
    [content addSubview:root];
    [NSLayoutConstraint activateConstraints:@[
        [root.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:24],
        [root.trailingAnchor constraintEqualToAnchor:content.trailingAnchor constant:-24],
        [root.topAnchor constraintEqualToAnchor:content.topAnchor constant:20],
        [root.bottomAnchor constraintEqualToAnchor:content.bottomAnchor constant:-18],
    ]];

    NSImageView *icon = [[NSImageView alloc] init];
    icon.image = [NSApp applicationIconImage];
    icon.imageScaling = NSImageScaleProportionallyUpOrDown;
    icon.translatesAutoresizingMaskIntoConstraints = NO;
    [icon.widthAnchor constraintEqualToConstant:64].active = YES;
    [icon.heightAnchor constraintEqualToConstant:64].active = YES;

    NSTextField *name = [self label:kAppTitle
                                font:[NSFont systemFontOfSize:22 weight:NSFontWeightSemibold]
                               color:[NSColor labelColor]];
    NSTextField *version = [self label:[NSString stringWithFormat:@"版本 %@", [self appVersionString]]
                                  font:[NSFont systemFontOfSize:12]
                                 color:[NSColor secondaryLabelColor]];
    NSTextField *developer = [self label:[NSString stringWithFormat:@"开发者 %@", kDeveloper]
                                    font:[NSFont systemFontOfSize:12]
                                   color:[NSColor secondaryLabelColor]];
    NSStackView *meta = [NSStackView stackViewWithViews:@[ name, version, developer ]];
    meta.orientation = NSUserInterfaceLayoutOrientationVertical;
    meta.alignment = NSLayoutAttributeLeading;
    meta.spacing = 2;
    meta.translatesAutoresizingMaskIntoConstraints = NO;

    NSStackView *header = [self rowWithViews:@[ icon, meta, [self gapView] ]];
    [root addArrangedSubview:header];
    [header.widthAnchor constraintEqualToAnchor:root.widthAnchor].active = YES;

    self.aboutSegment = [NSSegmentedControl segmentedControlWithLabels:@[ @"概览", @"更新日志", @"功能简介" ]
                                                          trackingMode:NSSegmentSwitchTrackingSelectOne
                                                                target:self
                                                                action:@selector(aboutTabChanged:)];
    self.aboutSegment.selectedSegment = 0;
    [root addArrangedSubview:self.aboutSegment];

    NSScrollView *scroll = [[NSScrollView alloc] init];
    scroll.translatesAutoresizingMaskIntoConstraints = NO;
    scroll.hasVerticalScroller = YES;
    scroll.autohidesScrollers = YES;
    scroll.borderType = NSNoBorder;
    scroll.drawsBackground = YES;
    scroll.backgroundColor = [NSColor controlBackgroundColor];
    scroll.wantsLayer = YES;
    scroll.layer.cornerRadius = 8;
    scroll.layer.borderWidth = 1;
    scroll.layer.borderColor = [NSColor separatorColor].CGColor;

    self.aboutTextView = [[NSTextView alloc] initWithFrame:NSMakeRect(0, 0, 560, 380)];
    self.aboutTextView.editable = NO;
    self.aboutTextView.selectable = YES;
    self.aboutTextView.drawsBackground = NO;
    self.aboutTextView.textContainerInset = NSMakeSize(12, 12);
    self.aboutTextView.textContainer.widthTracksTextView = YES;
    scroll.documentView = self.aboutTextView;
    [root addArrangedSubview:scroll];
    [scroll.widthAnchor constraintEqualToAnchor:root.widthAnchor].active = YES;
    [scroll.heightAnchor constraintGreaterThanOrEqualToConstant:350].active = YES;

    NSButton *close = [self button:@"关闭" action:@selector(closeAbout:)];
    close.keyEquivalent = @"\r";
    close.bezelColor = [NSColor controlAccentColor];
    NSStackView *footer = [self rowWithViews:@[ [self gapView], close ]];
    [root addArrangedSubview:footer];
    [footer.widthAnchor constraintEqualToAnchor:root.widthAnchor].active = YES;

    self.aboutWindow = w;
}

- (void)closeAbout:(id)sender {
    [self.aboutWindow orderOut:nil];
}

#pragma mark 设置

- (void)showSettings:(id)sender {
    if (!self.settingsWindow) [self buildSettingsWindow];
    [self.settingsWindow makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
}

- (NSStackView *)settingsExtensionRowWithLabel:(NSString *)title field:(NSTokenField *)field {
    NSTextField *label = [self label:title
                                font:[NSFont systemFontOfSize:12.5]
                               color:[NSColor labelColor]];
    [label.widthAnchor constraintEqualToConstant:56].active = YES;
    [field setContentHuggingPriority:1 forOrientation:NSLayoutConstraintOrientationHorizontal];
    [field setContentCompressionResistancePriority:750
                                    forOrientation:NSLayoutConstraintOrientationHorizontal];
    NSStackView *row = [NSStackView stackViewWithViews:@[ label, field ]];
    row.orientation = NSUserInterfaceLayoutOrientationHorizontal;
    row.alignment = NSLayoutAttributeCenterY;
    row.spacing = 10;
    row.translatesAutoresizingMaskIntoConstraints = NO;
    return row;
}

- (NSTokenField *)settingsTokenFieldWithValues:(NSArray<NSString *> *)values {
    NSTokenField *field = [[NSTokenField alloc] init];
    field.translatesAutoresizingMaskIntoConstraints = NO;
    field.font = [NSFont systemFontOfSize:12.5];
    field.tokenStyle = NSTokenStyleRounded;
    field.tokenizingCharacterSet = [NSCharacterSet characterSetWithCharactersInString:@",，、\n"];
    field.placeholderString = @"输入后回车";
    field.usesSingleLineMode = NO;
    field.maximumNumberOfLines = 0;
    field.cell.wraps = YES;
    field.objectValue = values;
    [field.heightAnchor constraintGreaterThanOrEqualToConstant:26].active = YES;
    return field;
}

- (void)buildSettingsWindow {
    NSWindow *w = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 720, 570)
                                              styleMask:(NSWindowStyleMaskTitled |
                                                         NSWindowStyleMaskClosable)
                                                backing:NSBackingStoreBuffered
                                                  defer:NO];
    w.title = @"设置";
    w.releasedWhenClosed = NO;

    NSView *content = w.contentView;
    NSStackView *root = [NSStackView new];
    root.orientation = NSUserInterfaceLayoutOrientationVertical;
    root.alignment = NSLayoutAttributeLeading;
    root.spacing = 10;
    root.translatesAutoresizingMaskIntoConstraints = NO;
    [content addSubview:root];
    [NSLayoutConstraint activateConstraints:@[
        [root.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:22],
        [root.trailingAnchor constraintEqualToAnchor:content.trailingAnchor constant:-22],
        [root.topAnchor constraintEqualToAnchor:content.topAnchor constant:18],
        [root.bottomAnchor constraintEqualToAnchor:content.bottomAnchor constant:-18],
    ]];

    NSTextField *title = [self label:@"文件类型"
                                font:[NSFont systemFontOfSize:14 weight:NSFontWeightSemibold]
                               color:[NSColor labelColor]];
    [root addArrangedSubview:title];

    NSTextField *hint = [self label:@"回车添加扩展名，点 × 删除；保存后下次扫描生效。预览文件只用于检测，默认不导入。"
                               font:[NSFont systemFontOfSize:11.5]
                              color:[NSColor secondaryLabelColor]];
    hint.maximumNumberOfLines = 3;
    hint.lineBreakMode = NSLineBreakByWordWrapping;
    [root addArrangedSubview:hint];
    [hint.widthAnchor constraintEqualToAnchor:root.widthAnchor].active = YES;

    self.imageExtField = [self settingsTokenFieldWithValues:
                          SavedExtensionList(kFileTypesImageKey, ImageExtensionList())];
    self.rawExtField = [self settingsTokenFieldWithValues:
                        SavedExtensionList(kFileTypesRawKey, RawExtensionList())];
    self.videoExtField = [self settingsTokenFieldWithValues:
                          SavedExtensionList(kFileTypesVideoKey, VideoExtensionList())];
    self.audioExtField = [self settingsTokenFieldWithValues:
                          SavedExtensionList(kFileTypesAudioKey, AudioExtensionList())];
    self.previewExtField = [self settingsTokenFieldWithValues:
                            SavedExtensionList(kFileTypesPreviewKey, PreviewExtensionList())];
    for (NSTokenField *field in @[ self.imageExtField, self.rawExtField, self.videoExtField,
                                   self.audioExtField, self.previewExtField ]) {
        field.placeholderString = @"输入扩展名后回车";
    }
    [self.imageExtField.heightAnchor constraintEqualToConstant:52].active = YES;
    [self.rawExtField.heightAnchor constraintEqualToConstant:80].active = YES;
    [self.videoExtField.heightAnchor constraintEqualToConstant:52].active = YES;
    [self.audioExtField.heightAnchor constraintEqualToConstant:52].active = YES;
    [self.previewExtField.heightAnchor constraintEqualToConstant:28].active = YES;

    NSArray<NSStackView *> *extensionRows = @[
        [self settingsExtensionRowWithLabel:@"图片" field:self.imageExtField],
        [self settingsExtensionRowWithLabel:@"RAW" field:self.rawExtField],
        [self settingsExtensionRowWithLabel:@"视频" field:self.videoExtField],
        [self settingsExtensionRowWithLabel:@"音频" field:self.audioExtField],
        [self settingsExtensionRowWithLabel:@"预览" field:self.previewExtField]
    ];
    for (NSUInteger i = 0; i < extensionRows.count; i++) {
        NSStackView *row = extensionRows[i];
        [root addArrangedSubview:row];
        [row.widthAnchor constraintEqualToAnchor:root.widthAnchor].active = YES;
        if (i + 1 < extensionRows.count) [root setCustomSpacing:4 afterView:row];
    }
    [root setCustomSpacing:12 afterView:extensionRows.lastObject];

    NSTextField *tagTitle = [self label:@"来源标签预设"
                                   font:[NSFont systemFontOfSize:14 weight:NSFontWeightSemibold]
                                  color:[NSColor labelColor]];
    [root addArrangedSubview:tagTitle];

    NSTextField *tagHint = [self label:@"输入后回车；点 × 移除。保存后立即更新来源标签下拉框。"
                                  font:[NSFont systemFontOfSize:11.5]
                                 color:[NSColor secondaryLabelColor]];
    [root addArrangedSubview:tagHint];

    self.tagPresetsTokenField = [self settingsTokenFieldWithValues:SourceTagPresets()];
    [root addArrangedSubview:self.tagPresetsTokenField];
    [self.tagPresetsTokenField.widthAnchor constraintEqualToAnchor:root.widthAnchor].active = YES;

    NSTextField *subTitle = [self label:@"子文件夹预设"
                                   font:[NSFont systemFontOfSize:14 weight:NSFontWeightSemibold]
                                  color:[NSColor labelColor]];
    [root addArrangedSubview:subTitle];

    NSTextField *subHint = [self label:@"输入后回车；这些会出现在「子文件夹 → 常用」的预设区。"
                                  font:[NSFont systemFontOfSize:11.5]
                                 color:[NSColor secondaryLabelColor]];
    [root addArrangedSubview:subHint];

    self.subfolderPresetsTokenField = [self settingsTokenFieldWithValues:SubfolderPresets()];
    [root addArrangedSubview:self.subfolderPresetsTokenField];
    [self.subfolderPresetsTokenField.widthAnchor constraintEqualToAnchor:root.widthAnchor].active = YES;

    NSButton *reset = [self button:@"恢复默认" action:@selector(resetSettingsEdits:)];
    NSView *gap = [self gapView];
    NSButton *close = [self button:@"关闭" action:@selector(closeSettings:)];
    close.keyEquivalent = @"\e";
    NSButton *save = [self button:@"保存" action:@selector(saveSettingsEdits:)];
    save.keyEquivalent = @"\r";
    save.bezelColor = [NSColor controlAccentColor];
    NSStackView *footer = [self rowWithViews:@[ reset, gap, close, save ]];
    [footer setCustomSpacing:10 afterView:close];
    [root addArrangedSubview:footer];
    [footer.widthAnchor constraintEqualToAnchor:root.widthAnchor].active = YES;

    self.settingsWindow = w;
}

- (void)closeSettings:(id)sender {
    [self.settingsWindow orderOut:nil];
}

- (void)reloadSourceTagPresets {
    NSString *current = self.sourceTagCombo.stringValue;
    [self.sourceTagCombo removeAllItems];
    [self.sourceTagCombo addItemsWithObjectValues:SourceTagPresets()];
    if (current.length) self.sourceTagCombo.stringValue = current;
}

- (void)showSettingsError:(NSString *)message {
    NSAlert *alert = [NSAlert new];
    alert.messageText = @"设置有误";
    alert.informativeText = message ?: @"请检查输入";
    alert.alertStyle = NSAlertStyleWarning;
    [alert addButtonWithTitle:@"好"];
    [alert beginSheetModalForWindow:self.settingsWindow completionHandler:nil];
}

- (void)saveSettingsEdits:(id)sender {
    NSArray<NSTokenField *> *extFields = @[ self.imageExtField, self.rawExtField,
                                            self.videoExtField, self.audioExtField,
                                            self.previewExtField ];
    NSArray<NSString *> *extKeys = @[ kFileTypesImageKey, kFileTypesRawKey, kFileTypesVideoKey,
                                      kFileTypesAudioKey, kFileTypesPreviewKey ];
    [self.tagPresetsTokenField validateEditing];
    [self.subfolderPresetsTokenField validateEditing];
    for (NSTokenField *field in extFields) [field validateEditing];

    NSMutableArray<NSArray<NSString *> *> *extLists = [NSMutableArray array];
    for (NSTokenField *field in extFields) {
        NSString *message = nil;
        NSArray<NSString *> *list = ExtensionsFromField(field, &message);
        if (!list) {
            [self showSettingsError:message ?: @"请检查扩展名"];
            return;
        }
        [extLists addObject:list];
    }

    NSArray<NSString *> *tags = TokenFieldValues(self.tagPresetsTokenField);
    NSArray<NSString *> *subs = TokenFieldValues(self.subfolderPresetsTokenField);
    if (!tags.count) {
        [self showSettingsError:@"至少保留一个来源标签预设"];
        return;
    }
    if (!subs.count) {
        [self showSettingsError:@"至少保留一个子文件夹预设"];
        return;
    }
    NSArray *reserved = @[ kOriginalPhotoName, kOriginalVideoName, @"（原始）" ];
    for (NSString *name in subs) {
        if ([reserved containsObject:name]) {
            [self showSettingsError:@"子文件夹预设不能使用（原始照片）/（原始视频）等保留名称"];
            return;
        }
    }

    for (NSUInteger i = 0; i < extFields.count; i++) {
        [[NSUserDefaults standardUserDefaults] setObject:extLists[i] forKey:extKeys[i]];
    }
    [[NSUserDefaults standardUserDefaults] setObject:tags forKey:kTagPresetsKey];
    [[NSUserDefaults standardUserDefaults] setObject:subs forKey:kSubfolderPresetsKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
    ReloadExtensionSets();
    [self reloadSourceTagPresets];

    for (NSUInteger i = 0; i < extFields.count; i++) {
        extFields[i].objectValue = extLists[i];
    }
    self.tagPresetsTokenField.objectValue = tags;
    self.subfolderPresetsTokenField.objectValue = subs;
    [self setStatus:@"✓ 设置已保存，下次扫描生效"];
    [self.settingsWindow orderOut:nil];
}

- (void)resetSettingsEdits:(id)sender {
    for (NSString *key in @[ kFileTypesImageKey, kFileTypesRawKey, kFileTypesVideoKey,
                             kFileTypesAudioKey, kFileTypesPreviewKey,
                             kTagPresetsKey, kSubfolderPresetsKey ]) {
        [[NSUserDefaults standardUserDefaults] removeObjectForKey:key];
    }
    [[NSUserDefaults standardUserDefaults] synchronize];
    ReloadExtensionSets();
    [self reloadSourceTagPresets];

    self.imageExtField.objectValue = ImageExtensionList();
    self.rawExtField.objectValue = RawExtensionList();
    self.videoExtField.objectValue = VideoExtensionList();
    self.audioExtField.objectValue = AudioExtensionList();
    self.previewExtField.objectValue = PreviewExtensionList();
    self.tagPresetsTokenField.objectValue = SourceTagPresets();
    self.subfolderPresetsTokenField.objectValue = SubfolderPresets();
    [self setStatus:@"已恢复默认设置"];
}

#pragma mark 单人 / 多人

- (void)maybeAskSwitchToMultiPersonWithCompletion:(void (^)(void))completion {
    void (^done)(void) = ^{ if (completion) completion(); };

    [self updatePersonModeLock];
    if (self.personModeLocked) { done(); return; }
    if (self.multiPerson) { done(); return; }

    NSMutableArray<NSString *> *named = [NSMutableArray array];
    for (NSString *name in self.detectedAuthors) {
        if (![name isEqualToString:kUnknownAuthorName] && ![named containsObject:name]) {
            [named addObject:name];
        }
    }
    if (named.count < 2) { done(); return; }

    if (getenv("DSH_SPLIT_AUTHOR")) {
        self.multiPerson = YES;
        self.personModeControl.selectedSegment = 1;
        [self computeDerivedSignatureState];
        done();
        return;
    }
    if (getenv("DSH_NO_ALERTS")) { done(); return; }

    NSString *list = [named componentsJoinedByString:@"、"];
    NSAlert *alert = [NSAlert new];
    alert.messageText = @"检测到多位作者";
    alert.informativeText = [NSString stringWithFormat:
        @"%@\n当前是单人模式，要切换到多人模式吗？\n多人模式下，原始照片 / 原始视频 内会按人名再分一层。",
        list];
    alert.alertStyle = NSAlertStyleInformational;
    [alert addButtonWithTitle:@"切换到多人模式"];
    [alert addButtonWithTitle:@"保持单人模式"];

    [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
        if (response == NSAlertFirstButtonReturn) {
            self.multiPerson = YES;
            self.personModeControl.selectedSegment = 1;
            [self updateSourceTagAvailability];
            [self computeDerivedSignatureState];
            [self refreshPreview];
            [self setStatus:[NSString stringWithFormat:@"已切换到多人模式：%@",
                             [[self currentPlan].authorFolderNames componentsJoinedByString:@"、"]]];
        }
        done();
    }];
}

- (void)postScanSignaturePrompts {
    [self presentSignatureConflictIfNeededWithCompletion:^{
        [self maybeAskUnknownAuthors];
    }];
}


#pragma mark 未知作者

- (NSString *)cameraSummaryForItem:(MediaItem *)item {
    if (item.meta.make.length && item.meta.model.length) {
        return [NSString stringWithFormat:@"%@ %@", item.meta.make, item.meta.model];
    }
    return item.meta.model.length ? item.meta.model : (item.meta.make ?: @"");
}


- (void)addNoIdentityFolderEntriesTo:(NSMutableDictionary<NSString *, NSMutableDictionary *> *)unknown
                               items:(NSArray<MediaItem *> *)items {
    NSMutableDictionary<NSString *, NSMutableDictionary *> *folders = [NSMutableDictionary dictionary];

    for (MediaItem *item in items) {
        if ([item.meta identityValues].count) continue;
        if ([self mappedSignatureForItem:item].length) continue;
        NSString *path = item.url.URLByDeletingLastPathComponent.path;
        if (!path.length) continue;
        NSString *key = [@"folder|" stringByAppendingString:path];
        if ([self.promptedUnknownAuthors containsObject:key]) continue;
        if (self.batchFolderPersonMappings[path].length) continue;

        NSMutableDictionary *folder = folders[key];
        if (!folder) {
            folder = [@{ @"path": path,
                         @"name": item.url.URLByDeletingLastPathComponent.lastPathComponent ?: @"",
                         @"files": [NSMutableArray array],
                         @"known": [NSMutableSet set] } mutableCopy];
            folders[key] = folder;
        }
        [folder[@"files"] addObject:item.url.lastPathComponent];
    }

    for (MediaItem *item in items) {
        if (![item.meta identityValues].count) continue;
        NSString *path = item.url.URLByDeletingLastPathComponent.path;
        if (!path.length) continue;
        NSMutableDictionary *folder = folders[[@"folder|" stringByAppendingString:path]];
        if (!folder) continue;
        NSString *person = [self personNameForItem:item];
        if (person.length) [folder[@"known"] addObject:person];
    }

    for (NSString *key in folders) {
        NSMutableDictionary *folder = folders[key];
        NSSet *known = folder[@"known"];
        NSString *inferred = known.count == 1 ? [known anyObject] : @"";
        NSArray *files = folder[@"files"];
        NSString *name = folder[@"name"] ?: @"";
        unknown[key] = [@{
            @"keyword": key,
            @"noIdentity": @YES,
            @"folderPath": folder[@"path"],
            @"folderName": name,
            @"inferred": inferred ?: @"",
            @"files": files,
            @"count": @(files.count),
            @"hasAuthor": @NO,
            @"author": @"",
            @"camera": @"",
            @"serial": @"",
            @"folderSet": [NSMutableSet setWithObject:name]
        } mutableCopy];
    }
}

- (NSArray<NSDictionary *> *)unknownAuthorsInItems:(NSArray<MediaItem *> *)items {
    if (!self.promptedUnknownAuthors) self.promptedUnknownAuthors = [NSMutableSet set];
    NSMutableDictionary<NSString *, NSMutableDictionary *> *unknown = [NSMutableDictionary dictionary];

    for (MediaItem *item in items) {
        if ([self mappedSignatureForItem:item].length) continue;

        NSString *author = SanitizeComponent(item.meta.artist ?: @"");
        NSString *keyword = author;
        if (!keyword.length) keyword = SanitizeComponent(item.meta.bodySerial ?: @"");
        if (!keyword.length) keyword = SanitizeComponent(item.meta.model ?: @"");
        if (!keyword.length) continue;  // 无身份素材按所在文件夹分组
        if ([self.promptedUnknownAuthors containsObject:keyword]) continue;

        NSMutableDictionary *entry = unknown[keyword];
        if (!entry) {
            entry = [@{ @"keyword": keyword,
                        @"author": author,
                        @"hasAuthor": @(author.length > 0),
                        @"noIdentity": @NO,
                        @"camera": [self cameraSummaryForItem:item] ?: @"",
                        @"serial": item.meta.bodySerial ?: @"",
                        @"count": @0,
                        @"folderSet": [NSMutableSet set] } mutableCopy];
            unknown[keyword] = entry;
        }
        NSString *parentFolder = item.url.URLByDeletingLastPathComponent.lastPathComponent;
        if (parentFolder.length) [entry[@"folderSet"] addObject:parentFolder];
        entry[@"count"] = @([entry[@"count"] integerValue] + 1);
        if (![entry[@"camera"] length]) entry[@"camera"] = [self cameraSummaryForItem:item] ?: @"";
        if (![entry[@"serial"] length]) entry[@"serial"] = item.meta.bodySerial ?: @"";
        if (author.length) entry[@"hasAuthor"] = @YES;
    }

    if (self.multiPerson) {
        [self addNoIdentityFolderEntriesTo:unknown items:items];
    }

    return [unknown.allValues sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        NSInteger ca = [a[@"count"] integerValue];
        NSInteger cb = [b[@"count"] integerValue];
        if (ca != cb) return ca > cb ? NSOrderedAscending : NSOrderedDescending;
        return [a[@"keyword"] localizedStandardCompare:b[@"keyword"]];
    }];
}

- (void)maybeAskUnknownAuthors {
    if (getenv("DSH_NO_ALERTS")) return;
    if (self.autoSignCheck.state != NSControlStateValueOn) return;
    if (!self.items.count) return;

    NSArray<NSDictionary *> *entries = [self unknownAuthorsInItems:self.items];
    if (!entries.count) return;
    [self presentUnknownAuthors:entries];
}

- (void)presentUnknownAuthors:(NSArray<NSDictionary *> *)entries {
    self.unknownEntries = entries;
    if (!self.unknownWindow) [self buildUnknownWindow];

    for (NSView *view in [self.unknownRowsStack.arrangedSubviews copy]) {
        [self.unknownRowsStack removeArrangedSubview:view];
        [view removeFromSuperview];
    }

    NSMutableArray<NSTextField *> *fields = [NSMutableArray array];
    NSMutableArray<NSButton *> *checks = [NSMutableArray array];
    for (NSUInteger i = 0; i < entries.count; i++) {
        NSTextField *field = nil;
        NSButton *check = nil;
        NSView *row = [self unknownRowForEntry:entries[i] index:i field:&field saveCheck:&check];
        [self.unknownRowsStack addArrangedSubview:row];
        [row.widthAnchor constraintEqualToAnchor:self.unknownRowsStack.widthAnchor].active = YES;
        [fields addObject:field];
        if (check) [checks addObject:check];
    }
    self.unknownFields = fields;
    self.unknownSaveChecks = checks;
    self.unknownFolderInferenceCheck.state = NSControlStateValueOn;
    [self updateUnknownFolderPrefills];
    [self updateUnknownFolderSaveAvailability];

    self.pendingInferenceAssignments = nil;
    __weak typeof(self) weakSelf = self;
    [self.window beginSheet:self.unknownWindow completionHandler:^(NSModalResponse response) {
        AppDelegate *strongSelf = weakSelf;
        NSArray<NSDictionary *> *pending = strongSelf.pendingInferenceAssignments;
        strongSelf.pendingInferenceAssignments = nil;
        if (pending.count) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.15 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                [strongSelf showFolderInferenceConfirmation:pending];
            });
        }
    }];

    if (getenv("DSH_AUTO_SAVE_UNKNOWN")) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [self saveUnknownAuthors:nil];
        });
    }
    if (getenv("DSH_AUTO_CANCEL_UNKNOWN")) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [self cancelUnknownAuthors:nil];
        });
    }
}

- (void)unknownFolderInferenceToggled:(id)sender {
    [self updateUnknownFolderPrefills];
    [self updateUnknownFolderSaveAvailability];
}

- (void)updateUnknownFolderSaveAvailability {
    if (!self.unknownFolderInferenceCheck) return;
    BOOL inferenceOn = (self.unknownFolderInferenceCheck.state == NSControlStateValueOn);
    for (NSUInteger i = 0; i < self.unknownEntries.count; i++) {
        NSDictionary *entry = self.unknownEntries[i];
        if (![entry[@"noIdentity"] boolValue]) continue;
        if (i >= self.unknownFields.count || i >= self.unknownSaveChecks.count) continue;
        NSString *name = Trim(self.unknownFields[i].stringValue);
        if (!name.length && inferenceOn) name = entry[@"inferred"] ?: @"";
        BOOL canSave = name.length && ![name isEqualToString:kUnknownAuthorName];
        NSButton *check = self.unknownSaveChecks[i];
        check.enabled = canSave;
        if (!canSave) check.state = NSControlStateValueOff;
    }
}

- (void)updateUnknownFolderPrefills {
    if (!self.unknownFolderInferenceCheck) return;
    BOOL on = self.unknownFolderInferenceCheck.state == NSControlStateValueOn;
    for (NSUInteger i = 0; i < self.unknownEntries.count && i < self.unknownFields.count; i++) {
        NSDictionary *entry = self.unknownEntries[i];
        if (![entry[@"noIdentity"] boolValue]) continue;
        NSString *inferred = entry[@"inferred"];
        NSTextField *field = self.unknownFields[i];
        if (on && !field.stringValue.length && inferred.length) {
            field.stringValue = inferred;
        } else if (!on && inferred.length && [field.stringValue isEqualToString:inferred]) {
            field.stringValue = @"";
        }
    }
}

- (void)buildUnknownWindow {
    NSWindow *w = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 760, 550)
                                              styleMask:NSWindowStyleMaskTitled
                                                backing:NSBackingStoreBuffered
                                                  defer:NO];
    w.title = @"未知身份";
    w.releasedWhenClosed = NO;

    NSView *content = w.contentView;
    NSStackView *root = [NSStackView new];
    root.orientation = NSUserInterfaceLayoutOrientationVertical;
    root.alignment = NSLayoutAttributeLeading;
    root.spacing = 10;
    root.translatesAutoresizingMaskIntoConstraints = NO;
    [content addSubview:root];
    [NSLayoutConstraint activateConstraints:@[
        [root.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:22],
        [root.trailingAnchor constraintEqualToAnchor:content.trailingAnchor constant:-22],
        [root.topAnchor constraintEqualToAnchor:content.topAnchor constant:18],
        [root.bottomAnchor constraintEqualToAnchor:content.bottomAnchor constant:-18],
    ]];

    NSTextField *title = [self label:@"发现未知身份"
                                font:[NSFont systemFontOfSize:14 weight:NSFontWeightSemibold]
                               color:[NSColor labelColor]];
    [root addArrangedSubview:title];

    NSTextField *hint = [self label:@"这些身份还没有署名对应关系。留空确认就用作者名 / 序列号 / 型号作为署名；没有作者信息的素材会按所在文件夹分组，勾选下面的选项时会优先归给同文件夹里唯一的作者。"
                               font:[NSFont systemFontOfSize:11.5]
                              color:[NSColor secondaryLabelColor]];
    hint.maximumNumberOfLines = 3;
    hint.lineBreakMode = NSLineBreakByWordWrapping;
    [root addArrangedSubview:hint];
    [hint.widthAnchor constraintEqualToAnchor:root.widthAnchor].active = YES;

    self.unknownFolderInferenceCheck = [NSButton checkboxWithTitle:@"根据上级文件夹分类未标注文件"
                                                            target:self
                                                            action:@selector(unknownFolderInferenceToggled:)];
    self.unknownFolderInferenceCheck.state = NSControlStateValueOn;
    self.unknownFolderInferenceCheck.font = [NSFont systemFontOfSize:11.5];
    self.unknownFolderInferenceCheck.toolTip = @"文件夹里只有一位作者时，把同文件夹里没有信息的文件归给他；保存后会列出文件名确认";
    [root addArrangedSubview:self.unknownFolderInferenceCheck];

    NSTextField *applyHint = [self label:@"点「保存并应用」后才会按文件夹归类并弹出确认；点「取消导入」会放弃这一批素材，不改动目录。"
                                   font:[NSFont systemFontOfSize:10.5]
                                  color:[NSColor tertiaryLabelColor]];
    applyHint.maximumNumberOfLines = 2;
    applyHint.lineBreakMode = NSLineBreakByWordWrapping;
    [root addArrangedSubview:applyHint];
    [applyHint.widthAnchor constraintEqualToAnchor:root.widthAnchor].active = YES;

    NSScrollView *scroll = [[NSScrollView alloc] init];
    scroll.translatesAutoresizingMaskIntoConstraints = NO;
    scroll.hasVerticalScroller = YES;
    scroll.autohidesScrollers = YES;
    scroll.borderType = NSNoBorder;
    scroll.drawsBackground = YES;
    scroll.backgroundColor = [NSColor controlBackgroundColor];
    scroll.wantsLayer = YES;
    scroll.layer.cornerRadius = 8;
    scroll.layer.borderWidth = 1;
    scroll.layer.borderColor = [NSColor separatorColor].CGColor;
    [scroll.heightAnchor constraintEqualToConstant:300].active = YES;

    self.unknownRowsStack = [FlippedStackView new];
    self.unknownRowsStack.orientation = NSUserInterfaceLayoutOrientationVertical;
    self.unknownRowsStack.alignment = NSLayoutAttributeLeading;
    self.unknownRowsStack.spacing = 8;
    self.unknownRowsStack.translatesAutoresizingMaskIntoConstraints = NO;
    scroll.documentView = self.unknownRowsStack;
    [NSLayoutConstraint activateConstraints:@[
        [self.unknownRowsStack.leadingAnchor constraintEqualToAnchor:scroll.contentView.leadingAnchor constant:10],
        [self.unknownRowsStack.trailingAnchor constraintEqualToAnchor:scroll.contentView.trailingAnchor constant:-10],
        [self.unknownRowsStack.topAnchor constraintEqualToAnchor:scroll.contentView.topAnchor constant:10],
    ]];
    [root addArrangedSubview:scroll];
    [scroll.widthAnchor constraintEqualToAnchor:root.widthAnchor].active = YES;

    NSView *gap = [self gapView];
    NSButton *cancel = [self button:@"取消导入" action:@selector(cancelUnknownAuthors:)];
    cancel.keyEquivalent = @"\e";
    NSButton *save = [self button:@"保存并应用" action:@selector(saveUnknownAuthors:)];
    save.keyEquivalent = @"\r";
    save.bezelColor = [NSColor controlAccentColor];
    NSStackView *footer = [self rowWithViews:@[ gap, cancel, save ]];
    [footer setCustomSpacing:10 afterView:cancel];
    [root addArrangedSubview:footer];
    [footer.widthAnchor constraintEqualToAnchor:root.widthAnchor].active = YES;

    self.unknownWindow = w;
}

- (NSView *)unknownRowForEntry:(NSDictionary *)entry
                         index:(NSUInteger)index
                         field:(NSTextField **)outField
                    saveCheck:(NSButton **)outCheck {
    BOOL hasAuthor = [entry[@"hasAuthor"] boolValue];
    BOOL noIdentity = [entry[@"noIdentity"] boolValue];
    NSMutableArray *parts = [NSMutableArray array];
    if (noIdentity) {
        [parts addObject:@"无作者信息"];
    } else {
        [parts addObject:(hasAuthor ? entry[@"author"] : @"未识别作者")];
        if ([entry[@"camera"] length]) [parts addObject:entry[@"camera"]];
        if ([entry[@"serial"] length]) [parts addObject:entry[@"serial"]];
    }
    [parts addObject:[NSString stringWithFormat:@"%ld %@",
                      (long)[entry[@"count"] integerValue],
                      noIdentity ? @"个文件" : @"张"]];
    NSString *meta = [parts componentsJoinedByString:@" · "];

    NSArray *folders = [[(NSSet *)entry[@"folderSet"] allObjects]
                        sortedArrayUsingSelector:@selector(localizedStandardCompare:)];
    NSArray *shown = folders.count > 2 ? [folders subarrayWithRange:NSMakeRange(0, 2)] : folders;
    NSString *folderText = [shown componentsJoinedByString:@"、"];
    if (folders.count > shown.count) folderText = [folderText stringByAppendingString:@"…"];
    NSString *folderLine = folderText.length
        ? [@"原文件夹：" stringByAppendingString:folderText] : @"";

    NSTextField *label = [self label:meta font:[NSFont systemFontOfSize:12] color:[NSColor labelColor]];
    label.lineBreakMode = NSLineBreakByTruncatingTail;
    label.toolTip = folderLine.length ? [meta stringByAppendingFormat:@"\n%@", folderLine] : meta;

    NSTextField *folderLabel = [self label:folderLine
                                     font:[NSFont systemFontOfSize:10.5]
                                    color:[NSColor secondaryLabelColor]];
    folderLabel.lineBreakMode = NSLineBreakByTruncatingTail;
    folderLabel.hidden = !folderLine.length;

    NSStackView *metaStack = [NSStackView stackViewWithViews:@[ label, folderLabel ]];
    metaStack.orientation = NSUserInterfaceLayoutOrientationVertical;
    metaStack.alignment = NSLayoutAttributeLeading;
    metaStack.spacing = 1;
    metaStack.translatesAutoresizingMaskIntoConstraints = NO;
    [metaStack.widthAnchor constraintEqualToConstant:330].active = YES;

    NSTextField *field = [NSTextField textFieldWithString:@""];
    if (noIdentity) {
        NSString *inferred = entry[@"inferred"];
        field.placeholderString = inferred.length
            ? [NSString stringWithFormat:@"留空则归入「%@」", inferred]
            : @"留空则用「未标注」";
    } else {
        field.placeholderString = [NSString stringWithFormat:@"留空则用「%@」", entry[@"keyword"]];
    }
    field.font = [NSFont systemFontOfSize:12.5];
    field.delegate = self;
    field.translatesAutoresizingMaskIntoConstraints = NO;
    field.tag = (NSInteger)index;
    [field.widthAnchor constraintEqualToConstant:190].active = YES;

    NSButton *saveCheck = [NSButton checkboxWithTitle:@"保存对应关系" target:nil action:nil];
    saveCheck.font = [NSFont systemFontOfSize:11.5];
    if (noIdentity) {
        BOOL inferred = ([entry[@"inferred"] length] > 0);
        saveCheck.title = @"保存对应关系";
        saveCheck.state = inferred ? NSControlStateValueOn : NSControlStateValueOff;
        saveCheck.enabled = inferred;
        saveCheck.toolTip = @"填了具体名字（不能是未标注）才能保存；保存后按文件夹名套用";
    } else {
        saveCheck.state = (hasAuthor || [entry[@"serial"] length]) ? NSControlStateValueOn
                                                                   : NSControlStateValueOff;
        saveCheck.toolTip = @"勾选后写入署名规则，下次同类照片自动套用；不勾选只对本次导入生效";
    }
    saveCheck.translatesAutoresizingMaskIntoConstraints = NO;
    [saveCheck.widthAnchor constraintEqualToConstant:105].active = YES;

    if (outField) *outField = field;
    if (outCheck) *outCheck = saveCheck;
    return [self rowWithViews:@[ metaStack, field, saveCheck ]];
}

- (void)saveUnknownAuthors:(id)sender {
    NSMutableArray *rules = [self.signRules mutableCopy];
    NSMutableSet *keywords = [NSMutableSet set];
    for (NSDictionary *rule in rules) {
        NSString *keyword = rule[@"keyword"];
        if ([keyword isKindOfClass:[NSString class]]) [keywords addObject:keyword];
    }
    NSMutableDictionary<NSString *, NSString *> *batch = [NSMutableDictionary dictionary];
    NSMutableDictionary<NSString *, NSString *> *folderMappings = [NSMutableDictionary dictionary];
    NSMutableArray<NSDictionary *> *inferredAssignments = [NSMutableArray array];
    BOOL inferenceOn = (self.unknownFolderInferenceCheck.state == NSControlStateValueOn);
    NSUInteger addedRules = 0;

    for (NSUInteger i = 0; i < self.unknownEntries.count; i++) {
        NSDictionary *entry = self.unknownEntries[i];
        NSString *keyword = entry[@"keyword"];
        if (!keyword.length) continue;
        NSString *signature = (i < self.unknownFields.count)
            ? Trim(self.unknownFields[i].stringValue) : @"";

        if ([entry[@"noIdentity"] boolValue]) {
            NSString *path = entry[@"folderPath"] ?: @"";
            NSString *inferred = entry[@"inferred"] ?: @"";
            NSString *name = signature;
            if (!name.length && inferenceOn && inferred.length) name = inferred;
            if (!name.length) name = kUnknownAuthorName;
            if (path.length) folderMappings[path] = name;

            NSString *folderName = Trim(entry[@"folderName"] ?: @"");
            BOOL shouldSave = (i < self.unknownSaveChecks.count)
                ? (self.unknownSaveChecks[i].state == NSControlStateValueOn) : NO;
            if (shouldSave && folderName.length &&
                ![name isEqualToString:kUnknownAuthorName] &&
                ![keywords containsObject:folderName]) {
                [rules addObject:@{ @"keyword": folderName, @"signature": name }];
                [keywords addObject:folderName];
                addedRules++;
            }

            if (inferenceOn && inferred.length && [name isEqualToString:inferred]) {
                [inferredAssignments addObject:@{ @"path": path,
                                                  @"person": inferred,
                                                  @"files": entry[@"files"] ?: @[] }];
            }
            continue;
        }

        if (!signature.length) signature = keyword;
        BOOL shouldSave = (i < self.unknownSaveChecks.count)
            ? (self.unknownSaveChecks[i].state == NSControlStateValueOn) : YES;
        if (shouldSave) {
            if (![keywords containsObject:keyword]) {
                [rules addObject:@{ @"keyword": keyword, @"signature": signature }];
                [keywords addObject:keyword];
                addedRules++;
            }
        } else {
            batch[keyword] = signature;
        }
    }

    self.batchSignatureMappings = batch;
    self.batchFolderPersonMappings = folderMappings;
    [self persistSignRules:rules];
    [self markUnknownAuthorsPrompted];
    self.pendingInferenceAssignments = inferredAssignments;
    [self closeUnknownSheet];
    [self computeDerivedSignatureState];
    [self refreshPreview];
    [self setStatus:addedRules > 0 ? @"已保存对应关系" : @"已应用对应关系（仅本次导入）"];
}

- (void)showFolderInferenceConfirmation:(NSArray<NSDictionary *> *)assignments {
    NSMutableString *list = [NSMutableString string];
    NSUInteger total = 0;
    for (NSDictionary *assignment in assignments) {
        NSArray *files = assignment[@"files"] ?: @[];
        total += files.count;
        [list appendFormat:@"%@（%lu 个）\n",
         assignment[@"person"] ?: @"", (unsigned long)files.count];
        for (NSString *file in files) {
            [list appendFormat:@"  • %@\n", file];
        }
        [list appendString:@"\n"];
    }

    NSAlert *alert = [NSAlert new];
    alert.messageText = @"按上级文件夹归类";
    alert.informativeText = [NSString stringWithFormat:
        @"以下文件没有作者信息，已按所在文件夹归给对应的人：\n\n%@", list];
    alert.alertStyle = NSAlertStyleInformational;
    [alert addButtonWithTitle:@"按文件夹归类"];
    [alert addButtonWithTitle:@"改为未标注"];
    [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
        if (response == NSAlertSecondButtonReturn) {
            for (NSDictionary *assignment in assignments) {
                NSString *path = assignment[@"path"];
                if (path.length) self.batchFolderPersonMappings[path] = kUnknownAuthorName;
            }
            [self computeDerivedSignatureState];
            [self refreshPreview];
            [self setStatus:@"已改为未标注"];
        } else {
            [self setStatus:[NSString stringWithFormat:
                             @"已按上级文件夹归类 %lu 个文件", (unsigned long)total]];
        }
    }];
}

- (void)cancelUnknownAuthors:(id)sender {
    self.pendingInferenceAssignments = nil;
    [self closeUnknownSheet];
    [self cancelImportBatch];
}

- (void)cancelImportBatch {
    self.items = @[];
    self.sourceURLs = @[];
    self.pendingPreviewURLs = @[];
    [self.batchSignatureMappings removeAllObjects];
    [self.batchFolderPersonMappings removeAllObjects];
    [self.promptedUnknownAuthors removeAllObjects];
    self.batchHasVideo = NO;
    self.detectedPhotoAuthors = @[];
    self.detectedVideoAuthors = @[];
    self.detectedAuthors = @[];
    self.autoSignature = nil;

    self.sourceLabel.stringValue = @"未选择照片 · 可直接拖入";
    self.sourceLabel.toolTip = nil;
    self.metaGrid.hidden = YES;
    self.autoSignNoteLabel.hidden = YES;
    self.importButton.enabled = NO;
    self.progress.hidden = YES;
    self.progress.doubleValue = 0;
    self.spinner.hidden = YES;
    self.verifyResultChip.hidden = YES;
    self.sourceTagRow.hidden = YES;
    self.categoryRow.hidden = YES;
    [self updateCategoryCounts:@[ @0, @0, @0, @0 ]];
    [self setBusy:NO];

    if (self.dateBeforeScan) {
        self.datePicker.dateValue = self.dateBeforeScan;
        self.dateBeforeScan = nil;
    }
    [self computeDerivedSignatureState];
    [self refreshAutoSignatureStatus];
    [self refreshPreview];
    [self setStatus:@"已取消本批导入"];
}

- (void)markUnknownAuthorsPrompted {
    if (!self.promptedUnknownAuthors) self.promptedUnknownAuthors = [NSMutableSet set];
    for (NSDictionary *entry in self.unknownEntries) {
        NSString *keyword = entry[@"keyword"];
        if (keyword.length) [self.promptedUnknownAuthors addObject:keyword];
    }
}

- (void)closeUnknownSheet {
    [self.window endSheet:self.unknownWindow];
    [self.unknownWindow orderOut:nil];
}

#pragma mark 执行

- (void)createFolders:(id)sender {
    if (self.busy) return;
    [self.window makeFirstResponder:nil];
    if (![self validateSignature]) return;
    ArchivePlan *plan = [self currentPlan];
    NSError *error = nil;
    NSArray<NSURL *> *created = CreateDirectories(plan, &error);
    if (error) {
        ShowError(self.window, @"无法创建文件夹", error.localizedDescription);
        return;
    }
    [self saveSettings];
    [self recordSubfolderUsage:[plan effectiveSubfolders]];
    NSString *path = AbbreviatePath([plan eventDirectoryURL] ? [plan eventDirectoryURL].path
                                                             : plan.rootURL.path);
    if (created.count) {
        [self setStatus:[NSString stringWithFormat:@"✓ 已创建 %lu 个文件夹 · %@",
                         (unsigned long)created.count, path]];
    } else {
        [self setStatus:[NSString stringWithFormat:@"✓ 目录已就绪（已存在）· %@", path]];
    }
    self.revealButton.enabled = YES;
    [self refreshPreview];
}

- (void)importPhotos:(id)sender {
    if (self.busy || !self.items.count) return;
    [self.window makeFirstResponder:nil];
    if (![self validateSignature]) return;

    NSArray<NSURL *> *files = [self.items valueForKey:@"url"];
    ArchivePlan *plan = [self currentPlan];
    BOOL move = (self.moveRadio.state == NSControlStateValueOn);

    NSError *error = nil;
    CreateDirectories(plan, &error);
    if (error) {
        ShowError(self.window, @"无法创建文件夹", error.localizedDescription);
        return;
    }
    [self saveSettings];
    [self recordSubfolderUsage:[plan effectiveSubfolders]];

    [self setBusy:YES];
    self.progress.hidden = NO;
    self.progress.doubleValue = 0;
    if (plan.verifyCopies) {
        [self.verifyResultChip setStatusText:@"校验中…"
                                       color:[NSColor colorWithSRGBRed:0.42 green:0.42 blue:0.44 alpha:1.0]
                                     tooltip:@"正在计算源文件与目标文件的哈希"];
        self.verifyResultChip.hidden = NO;
    } else {
        self.verifyResultChip.hidden = YES;
    }
    [self setStatus:[NSString stringWithFormat:@"正在%@%lu 个文件%@…", move ? @"移动" : @"复制",
                     (unsigned long)files.count, plan.verifyCopies ? @"并校验" : @""]];

    NSMutableDictionary<NSString *, NSString *> *authorByPath = [NSMutableDictionary dictionary];
    for (MediaItem *item in self.items) {
        NSString *person = [self personNameForItem:item];
        if (person.length && item.url.path) authorByPath[item.url.path] = person;
    }

    NSMutableSet<NSString *> *videoLikePaths = [NSMutableSet set];
    for (MediaItem *item in self.items) {
        if (item.previewFile && item.url.path) [videoLikePaths addObject:item.url.path];
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        ImportResult *result = [ImportResult new];
        ImportItems(plan, files, authorByPath, videoLikePaths, move, ^(NSInteger done, NSInteger total) {
            if (done % 3 == 0 || done == total) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    self.progress.doubleValue = total ? (double)done / (double)total : 0;
                });
            }
        }, result);

        dispatch_async(dispatch_get_main_queue(), ^{
            [self setBusy:NO];
            self.progress.doubleValue = 0;
            NSString *verb = move ? @"移动" : @"复制";
            NSString *destName = plan.includesVideo
                ? [NSString stringWithFormat:@"%@ / %@", kOriginalPhotoName, kOriginalVideoName]
                : kOriginalPhotoName;
            NSMutableString *msg = [NSMutableString stringWithFormat:@"✓ 已%@ %ld 个文件到 %@",
                                    verb, (long)(move ? result.moved : result.copied), destName];
            if (plan.sourceTag.length) [msg appendFormat:@" · 标签：%@", [plan cleanSourceTag]];
            if (plan.verifyCopies) {
                [msg appendFormat:@" · 校验通过 %ld", (long)result.verified];
                if (result.verifyFailed) [msg appendFormat:@" · 校验失败 %ld", (long)result.verifyFailed];
            }
            if (result.skipped) [msg appendFormat:@" · 跳过重复 %ld", (long)result.skipped];
            if (result.renamed) [msg appendFormat:@" · 重名改名 %ld", (long)result.renamed];
            if (result.failed) [msg appendFormat:@" · 失败 %ld", (long)result.failed];
            if (plan.verifyCopies) {
                NSString *algorithm = (plan.verifyKind == 1) ? @"MD5" : @"xxHash64";
                if (result.verifyFailed > 0) {
                    [self.verifyResultChip setStatusText:
                        [NSString stringWithFormat:@"校验失败 %ld", (long)result.verifyFailed]
                                                   color:[NSColor colorWithSRGBRed:0.82 green:0.16 blue:0.15 alpha:1.0]
                                                 tooltip:[NSString stringWithFormat:@"%@ 校验未通过，目标副本已删除", algorithm]];
                    self.verifyResultChip.hidden = NO;
                } else if (result.verified > 0) {
                    [self.verifyResultChip setStatusText:
                        [NSString stringWithFormat:@"校验通过 %ld", (long)result.verified]
                                                   color:[NSColor colorWithSRGBRed:0.10 green:0.55 blue:0.25 alpha:1.0]
                                                 tooltip:[NSString stringWithFormat:@"已用 %@ 校验 %ld 个文件", algorithm, (long)result.verified]];
                    self.verifyResultChip.hidden = NO;
                } else {
                    self.verifyResultChip.hidden = YES;
                }
            } else {
                self.verifyResultChip.hidden = YES;
            }
            [self setStatus:msg];
            self.revealButton.enabled = YES;
            [self refreshPreview];

            if (result.failed) {
                NSString *detail = [[result.errors subarrayWithRange:
                                     NSMakeRange(0, MIN((NSUInteger)8, result.errors.count))]
                                    componentsJoinedByString:@"\n"];
                ShowError(self.window, @"部分文件未能归档", detail);
            }
        });
    });
}

- (void)revealInFinder:(id)sender {
    ArchivePlan *plan = [self currentPlan];
    NSURL *url = plan.flatMode ? [plan originalPhotoDirectoryURL] : [plan eventDirectoryURL];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (url && [fm fileExistsAtPath:url.path]) {
        [[NSWorkspace sharedWorkspace] activateFileViewerSelectingURLs:@[ url ]];
        return;
    }
    NSURL *root = plan.rootURL;
    if ([fm fileExistsAtPath:root.path]) {
        [[NSWorkspace sharedWorkspace] openURL:root];
    } else {
        [[NSWorkspace sharedWorkspace] openURL:[root URLByDeletingLastPathComponent]];
    }
}

@end

#pragma mark - 命令行模式

static NSDate *ParseDayString(NSString *text) {
    static NSDateFormatter *f;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        f = [NSDateFormatter new];
        f.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
        f.dateFormat = @"yyyy-MM-dd";
    });
    return [f dateFromString:Trim(text)];
}

static void PrintUsage(void) {
    printf("自动归档 — 按标准建立归档目录\n\n");
    printf("用法：\n");
    printf("  自动归档 --create --root 目录 --date 2026-10-19 --event 毕业典礼 [--sign 张三] [--flat] [--subs \"（筛选）,（收集）\"]\n");
    printf("  自动归档 --import --root 目录 --date 2026-10-19 --event 毕业典礼 --source 照片目录 [--sign 张三] [--verify md5] [--move] [--flat] [--keep-preview]\n\n");
    printf("原始照片 / 原始视频会自动创建并分流，--subs 只填附加文件夹。\n");
    printf("不附带 --create / --import 时启动图形界面。\n");
}

static int RunCLI(NSArray<NSString *> *args) {
    BOOL create = NO, import = NO, flat = NO, move = NO, verify = NO, keepPreview = NO;
    NSInteger verifyKind = 0;
    NSMutableDictionary<NSString *, NSString *> *opts = [NSMutableDictionary dictionary];

    for (NSUInteger i = 0; i < args.count; i++) {
        NSString *arg = args[i];
        if ([arg isEqualToString:@"--create"]) { create = YES; continue; }
        if ([arg isEqualToString:@"--import"]) { import = YES; continue; }
        if ([arg isEqualToString:@"--flat"]) { flat = YES; continue; }
        if ([arg isEqualToString:@"--move"]) { move = YES; continue; }
        if ([arg isEqualToString:@"--keep-preview"]) { keepPreview = YES; continue; }
        if ([arg isEqualToString:@"--verify"]) {
            verify = YES;
            if (i + 1 < args.count && ![args[i + 1] hasPrefix:@"--"] &&
                ([args[i + 1] isEqualToString:@"md5"] || [args[i + 1] isEqualToString:@"xxhash"])) {
                verifyKind = [args[i + 1] isEqualToString:@"md5"] ? 1 : 0;
                i++;
            }
            continue;
        }
        if ([arg isEqualToString:@"--help"] || [arg isEqualToString:@"-h"]) { PrintUsage(); return 0; }
        if ([arg hasPrefix:@"--"]) {
            if (i + 1 >= args.count) {
                fprintf(stderr, "参数 %s 缺少取值\n", arg.UTF8String);
                return 2;
            }
            opts[[arg substringFromIndex:2]] = args[++i];
        }
    }

    if (!create && !import) { PrintUsage(); return 2; }

    NSString *root = opts[@"root"] ?: [NSHomeDirectory() stringByAppendingPathComponent:@"Pictures/自动归档"];
    NSString *dateText = opts[@"date"] ?: @"";
    NSDate *day = dateText.length ? ParseDayString(dateText) : [NSDate date];
    if (!day) {
        fprintf(stderr, "无法识别的日期：%s（应为 2026-10-19）\n", dateText.UTF8String);
        return 2;
    }

    ArchivePlan *plan = [ArchivePlan new];
    plan.rootURL = [NSURL fileURLWithPath:[root stringByExpandingTildeInPath] isDirectory:YES];
    plan.date = day;
    plan.event = opts[@"event"] ?: @"";
    plan.flatMode = flat;
    plan.manualSignature = opts[@"sign"] ?: @"";
    plan.sourceTag = opts[@"tag"] ?: @"";
    plan.verifyCopies = verify;
    plan.verifyKind = verifyKind;
    plan.subfolders = opts[@"subs"] ? ParseSubfolders(opts[@"subs"]) : nil;

    NSArray<NSURL *> *files = nil;
    NSMutableSet<NSString *> *videoLikePaths = [NSMutableSet set];
    if (import) {
        NSString *source = opts[@"source"];
        if (!source.length) {
            fprintf(stderr, "缺少 --source\n");
            return 2;
        }
        NSURL *sourceURL = [NSURL fileURLWithPath:[source stringByExpandingTildeInPath] isDirectory:YES];
        files = CollectMediaURLs(@[ sourceURL ]);
        if (keepPreview) {
            NSArray<NSURL *> *previews = CollectPreviewURLs(@[ sourceURL ]);
            if (previews.count) {
                files = [files arrayByAddingObjectsFromArray:previews];
                for (NSURL *url in previews) [videoLikePaths addObject:url.path];
                plan.includesVideo = YES;
            }
        }
        if (!files.count) {
            fprintf(stderr, "没有在 %s 找到照片\n", source.UTF8String);
            return 1;
        }
        for (NSURL *file in files) {
            if ([MovieExtensions() containsObject:file.pathExtension.lowercaseString] ||
                [AudioExtensions() containsObject:file.pathExtension.lowercaseString]) {
                plan.includesVideo = YES;
                break;
            }
        }
    }

    NSError *error = nil;
    NSArray<NSURL *> *created = CreateDirectories(plan, &error);
    if (error) {
        fprintf(stderr, "创建失败：%s\n", error.localizedDescription.UTF8String);
        return 1;
    }
    printf("已创建 %lu 个文件夹\n%s", (unsigned long)created.count, plan.treeText.UTF8String);

    if (import) {
        ImportResult *result = [ImportResult new];
        ImportItems(plan, files, nil, videoLikePaths, move, NULL, result);
        printf("%s %ld 个 · 跳过重复 %ld 个 · 重名改名 %ld 个 · 失败 %ld 个",
               move ? "移动" : "复制",
               (long)(move ? result.moved : result.copied),
               (long)result.skipped, (long)result.renamed, (long)result.failed);
        if (verify) printf(" · 校验通过 %ld 个", (long)result.verified);
        printf("\n");
        for (NSString *line in result.errors) {
            fprintf(stderr, "  %s\n", line.UTF8String);
        }
        if (result.failed) return 1;
    }
    return 0;
}

#pragma mark - main

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSArray<NSString *> *args = [NSProcessInfo processInfo].arguments;
        if (args.count > 1 && [args[1] hasPrefix:@"--"]) {
            return RunCLI([args subarrayWithRange:NSMakeRange(1, args.count - 1)]);
        }

        NSApplication *app = [NSApplication sharedApplication];
        [app setActivationPolicy:NSApplicationActivationPolicyRegular];
        static AppDelegate *delegate;
        delegate = [AppDelegate new];
        app.delegate = delegate;
        [app run];
    }
    return 0;
}
