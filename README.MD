# Simple and minimalistic logger

## Objective of the project

Main goals I wanted to achieve in this project:

### Minimalistic design.

This means that this is not a universal solution.

### Minimum third-party dependencies.
 
Used: `STL`, `fmt`, `System API`, `C/C++` language extensions (for `fmt`).

In the future, `fmt` is likely to become part of the `STL` standard library.
 
### Cross-platform.
 
Tested on systems: `Windows`, `Linux`, `MSYS2`.

### Modern.
 
The latest used language version (C++20), at the current moment.
 
### Performance.
 
Messages are written in a separate thread. The number of I/O operations is reduced.

## Main Features / Usage.

### Create

First you need to create an object in one of the following ways:
 
```c++
auto loglevel = ELevel::trace;
bool is_syslog = false; /* put message to system journal */
bool is_sysout = true; /* print message to stdeout/stderror */

Loggerlog0;
Logger log9(ELevel::trace);
Logger log7(ELevel::trace, false, true);
Logger log1("../log/logfile1.log");
Logger log2("../log/logfile1.log", ELevel::trace);
```

## General project settings

If some parameters were not set when creating the object, then the default values specified in the `CMakeLists.txt` file are used:
 
```cmake
set(DEFAULT_APP_NAME ${CMAKE_PROJECT_NAME})
set(DEFAULT_ERROR_LEVEL warning)
set(DEFAULT_SIZE_LIMIT 1048576)
set(DEFAULT_DEPTH_LIMIT 10)
set(DEFAULT_SYSOUT_FLAG 1)
set(DEFAULT_SYSLOG_FLAG 0)
```
 
### Options
 
After creating the logging object, some parameters can be changed\configured using the `set` method:
 
```c++
logf.set(LoggerId::level, ELevel::trace);
logf.set(LoggerId::syslog, false);
logf.set(LoggerId::sysout, true);
logf.set(LoggerId::size, 1000000);
if (logf.set(LoggerId::depth, 32) == false) {
    std::cerr << "Unable set logger depth" << std:endl;
}
```
 
The `level` parameter - set the error level.

The `size` parameter is the number of characters in the log file, after which the "log rotation" occurs.

The `depth` parameter is the depth at which log files are stored.

The `sysout` option is to duplicate the message to standard output when available.

The `syslog` parameter is to duplicate the message in the system log.

> Some parameters (size, depth) affect all objects that have the same key, the rest are individual for each object.

### Logging

You can create a message in three different ways, as you like:

```c++
int id = 0;
logf.error("%s %s #%d", "hello", "world", ++id);
logf.warn() << "hello world #" << ++id << std::endl;
logf.d("{:s} {:s} #{:d}", "hello", "world", id);
```

## Additional description

 - Messages to syslog or stdout are sent immediately, which has a bad effect on the performance of the logger, but in my opinion, performance is not the most important feature, and if this is important to you, then something may be wrong with the architecture of the project.
 
 - If you want to get maximum performance, then you should disable `sysout` and `syslog`, make `size` as large as possible and `depth` as small as possible.
 
 - There is no need to close the log, it will happen automatically in case of successful completion of the program.