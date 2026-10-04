TARGET = litehook_tests

CC = clang

CFLAGS_MACOS = -arch arm64 -arch arm64e
CFLAGS_IOS   = -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -arch arm64e -miphoneos-version-min=10.0
CFLAGS       = -I../src -I../external/include
LDFLAGS      = -framework Foundation -framework CoreServices -framework Security

all: $(TARGET).ios $(TARGET).macos sign

sign: $(TARGET).ios
	@ldid -Sentitlements.plist $<

$(TARGET).ios: $(wildcard *.c ../src/*.c)
	$(CC) $(CFLAGS) $(CFLAGS_IOS) $(LDFLAGS) -o $@ $^

$(TARGET).macos: $(wildcard *.c ../src/*.c)
	$(CC) $(CFLAGS) $(CFLAGS_MACOS) $(LDFLAGS) -o $@ $^

clean:
	@rm -f $(TARGET).macos
	@rm -f $(TARGET).ios