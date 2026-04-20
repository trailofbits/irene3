# Test fixture sources

Reproduction recipes for every fixture compiled by irene-ghidra
maintainers. Rebuild when toolchains change.

## arm64-macos-collatz

```c
// collatz.c
unsigned collatz(unsigned n) {
  unsigned s = 0;
  while (n != 1) { n = (n & 1) ? 3*n + 1 : n/2; s++; }
  return s;
}
int main(int argc, char **argv) { return collatz(argc); }
```

Build:
```
clang -target arm64-apple-macos14 -O1 -o arm64-macos-collatz collatz.c
```

## arm64-macos-objc-hello.dylib

```objc
// Hello.m
#import <Foundation/Foundation.h>
@interface Hello : NSObject
- (NSString *)greet:(NSString *)name;
@end
@implementation Hello
- (NSString *)greet:(NSString *)name {
  return [NSString stringWithFormat:@"Hello, %@", name];
}
@end
```

Build:
```
clang -target arm64-apple-macos14 -dynamiclib -fobjc-arc \
      -framework Foundation -o arm64-macos-objc-hello.dylib Hello.m
```

## arm64-macos-objc-categories.dylib

Exercises ObjC protocol + category extraction (Phase 7.1). Defines
one protocol `Greeter`, a class `Hello` conforming to it, and a
category `Hello (Loud)` adding a `shout:` selector.

```objc
// Greeter.m
#import <Foundation/Foundation.h>

@protocol Greeter <NSObject>
- (NSString *)greet:(NSString *)name;
@end

@interface Hello : NSObject <Greeter>
@end

@implementation Hello
- (NSString *)greet:(NSString *)name {
    return [NSString stringWithFormat:@"Hello, %@", name];
}
@end

@interface Hello (Loud)
- (NSString *)shout:(NSString *)name;
@end

@implementation Hello (Loud)
- (NSString *)shout:(NSString *)name {
    return [[self greet:name] uppercaseString];
}
@end
```

Build:
```
clang -target arm64-apple-macos14 -dynamiclib -fobjc-arc \
      -framework Foundation -o arm64-macos-objc-categories.dylib Greeter.m
```

## arm64-macos-swift-hello

```swift
// hello.swift
public func greet(_ name: String) -> String { "Hello, \(name)" }

@main
struct App {
    static func main() { print(greet("Irene")) }
}
```

Build:
```
swiftc -parse-as-library -target arm64-apple-macos14 -O \
       -o arm64-macos-swift-hello hello.swift
```

`-parse-as-library` is required because `@main` cannot coexist with
top-level code in a file parsed as a script.

## arm64e-macos-sample

Same source as `arm64-macos-collatz`. PAC return-address signing is
implicit under `-target arm64e-*`; do **not** pass
`-mbranch-protection=pac-ret+bti` (it conflicts with
`-fptrauth-returns` which the arm64e triple enables automatically).

Build:
```
clang -target arm64e-apple-macos14 -O1 -o arm64e-macos-sample collatz.c
```

Verify the binary is actually arm64e:
```
otool -hv arm64e-macos-sample | head -3
# should show: cputype ARM64, cpusubtype E, caps USR01
```

## arm64-ios-encrypted-stub

Synthetic fixture: a real iOS Mach-O with `cryptid` flipped from 0 to 1
so it triggers the FairPlay-detection branch. `__TEXT` is **not**
actually encrypted.

Build:
```
xcrun --sdk iphoneos clang -target arm64-apple-ios14 -O1 \
      -o arm64-ios-collatz collatz.c
python3 build-encrypted-stub.py arm64-ios-collatz arm64-ios-encrypted-stub
```

`build-encrypted-stub.py` ships alongside the fixtures and only uses
stdlib `struct`. It locates the `LC_ENCRYPTION_INFO_64` load command
and writes `1` to its `cryptid` field. It does not re-sign the binary,
so `codesign --verify` will fail — that is intentional.
