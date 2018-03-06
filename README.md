# AntiDBG

AntiDBG is a collection of Windows Anti Debugging techniques. The techniques are categorized by the methods they use to find a debugger. 

  - Memory
  - CPU
  - Timing
  - Forced Exceptions

### AntiDBG API
AntiDBG is written in C and requires only a single source file and header. Nearly all of these methods are designed to take no input and produce no output. They aim to be self-contained debugger checks that will automatically detach debuggers.

### Obfuscation
AntiDBG is designed to be *readable* so the user can learn about the techniques. If you choose to use these methods in your own project, you will benefit greatly by adding obfuscation on top of these methods. Obfuscation is not the aim of this project.

### The Gauntlet
The Gauntlet is a simple application that runs each AntiDBG check one after the other. It's purpose is to test your ability to bypass the anti-debugging methods and make it to the end of The Gauntlet while running under a debugger.

Want to make The Gauntlet *harder*? Undefine SHOW_DEBUG_MESSAGES (defined by default in antidbg.c). This option produces a message box when you get caught with information about the check that got you.

### Troubleshooting

> Help! This thing won't compile!

AntiDBG was developed using Microsoft Visual Studio 2015 building as Release x86. If you are getting compiler errors, ensure you are building for x86. Many of these methods *will work* on x64 however they may require modification where inline assembly is used. 

> Help! X method doesn't seem to work.

Many anti-debugging checks focus on odd edge cases or very specific structures which may or may not be set on certain versions of Windows, or they may act differently under emulation. Some checks require the the debugger to step over the check, while others do not. All methods in AntiDBG have been tested under the conditions which they are designed work on Windows 10 64-bit. Most (if not all) should work on all over versions of Windows as well. AntiDBG shies away from checks which can only be used against specific debuggers or versions of Windows. 
