# AntiDBG

AntiDBG is a collection of Windows Anti Debugging techniques. The techniques are categorized by the methods they use to find a debugger. 

  - Memory
  - CPU
  - Timing
  - Forced Exceptions
  - Other

### Demos!

Want to see this stuff in action? Check out the [playlist on YouTube](https://www.youtube.com/playlist?list=PLxgggb3Nxh7s0uLlDinGVAsbi6o0pWv2X).

### AntiDBG API
AntiDBG is written in C and requires only a single source file and header. Nearly all of these methods are designed to take no input and produce no output. They aim to be self-contained debugger checks that will automatically detach debuggers.

### Obfuscation
AntiDBG is designed to be *readable* so the user can learn about the techniques. If you choose to use these methods in your own project, you will benefit greatly by adding obfuscation on top of these methods. Obfuscation is not the aim of this project.

### The Gauntlet
The Gauntlet is a simple application that runs each AntiDBG check one after the other. It's purpose is to test your ability to bypass the anti-debugging methods and make it to the end of The Gauntlet while running under a debugger.

Want to make The Gauntlet *harder*? Undefine SHOW_DEBUG_MESSAGES (defined by default in AntiDBG.cpp). This option produces a message box when you get caught with information about the check that got you.

### FAQ & Troubleshooting

> Help! X method doesn't seem to work.

Many anti-debugging checks focus on odd edge cases. Some require you to single step past, some require a specific debugger to be used, some require you to pass the exception to the debugger, etc.

All methods in AntiDBG have been tested under the conditions which they are designed work on Windows 10 64-bit. Most (if not all) should work on all other versions of Windows as well.

> Help! This thing won't compile!

AntiDBG was developed and tested using Microsoft Visual Studio 2019. As long as you're using 2019, please submit an issue with details and I'd be happy to help.

> Why is x86 assembly inline while x64 variants are in a .asm file?

Microsoft thought it would be a great idea to stop allowing developers to write inline assembly for x64. I don't know why, but the common reason I see cited around the internet is that developers suck at writing assembly and compilers are way better. While I don't disagree with this, I doubt that's the real reason. Whatever the reason, we now have to jump through hoops to do something even remotely similar. Huge thanks to [lallouslab](http://lallouslab.net/2016/01/11/introduction-to-writing-x64-assembly-in-visual-studio/) and [onipot](https://onipot.altervista.org/how-to-create-assembly-project-visual-studio-2019-64-bit/) for guiding me through this minefield.

> I have more questions.

I'd be happy to answer them! Please submit a GitHub issue with your questions and I'll try my best to help as soon as possible.

### Thanks

Thanks to the [contributors](https://github.com/HackOvert/AntiDBG/graphs/contributors) and everyone who has provided feedback in the past on this project.
