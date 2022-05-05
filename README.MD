# Simple & minimalistic C++ logger library

## Features

 - Minimalistic design (~500 lines of code)
 - Use more than one instance
 - Minimum third-party dependencies
 - Cross-platform (`gcc`, `mingw`, `msvc`)
 - Modern (`c++20`)
 - Thread-safe
 - Header only
 - Simple integration (`cmake`)
 - System log (`Windows`/`Linux`)
 - Three most used `APIs` (`printf`, `format`, `ostream`)
 - Asynchronous lazy writing in a separate thread
 - Colored console output supported
 - Log file rotation (by size)

## How to build

```bash
$ cmake .. && cmake --build .
```
> The library is designed to be easy to add to a cmake project as a git submodule.

> This library has a dependency on [flags](https://github.com/piratkin/logger)!

## How to use

First you need to create an object in one of the following ways:
 
```c++
auto loglevel = ELevel::trace;
bool is_syslog = false; /* also send message to syslog */
bool is_sysout = true; /* also send message to standart output */
bool is_color = true; /* colorful output */

Logger log0;
Logger log1(ELevel::trace);
Logger log2(ELevel::trace, is_syslog, is_sysout, is_color);
Logger log3("../log/logfile1.log");
Logger log4("../log/logfile1.log", ELevel::trace);
```

Six levels of logging available: `fatal`, `error`, `warn`, `info`, `debug`, `trace`.

Levels below `error` are printed to standard output, the rest to standard error.

The `fatal` level message prints a message and terminates the program.

After creating the logging object, some parameters can be changed\configured using the `set` method:
 
```c++
/* set error level */
log0.set(LoggerId::level, ELevel::trace);

/* duplicate message in system log */
log0.set(LoggerId::syslog, false);

/* duplicate message in standard output */
log0.set(LoggerId::sysout, true);

/* set logger file size */
log0.set(LoggerId::size, 1000000);

/* log file storage depth */
if (logf.set(LoggerId::depth, 32) == false) {
    std::cerr << "Unable set logger depth" << std:endl;
}

/* set colorful print */
logf.set(LoggerId::color, true);
```  

`set` returns `true` if successful, `false` otherwise.

Some parameters (`size`, `depth`) affect all objects that have the same `logfile`, the rest are individual for each object.

When `size` = 0, log rotation will be disabled.

You can create a message in three different ways, as you like:

```c++
int id = 0;

/* printf style (error) */
log0.error("%s %s #%d", "hello", "world", ++id);

/* ostream style (warning) */
log0.warn() << "hello world #" << ++id << std::endl;

/* format style (debug) */
log0.d("{:s} {:s} #{:d}", "hello", "world", ++id);
```

Output:

```bash
2022-04-20 18:53:40.911 ERROR [main@10] hello world #1
2022-04-20 18:53:40.916 WARN  [main@11] hello world #2
2022-04-20 18:53:40.916 DEBUG [main@12] hello world #3
```

## Additionally

 - Messages to syslog or stdout are sent immediately, which has a bad effect on the performance of the logger, but in my opinion, performance is not the most important feature, and if this is important to you, then something may be wrong with the architecture of the project.
 
 - If you want to get maximum performance, then you should disable `sysout` and `syslog`, make `size` as large as possible and `depth` as small as possible.
 
 - There is no need to close the log, it will happen automatically in case of successful completion of the program.

 - Do not set `depth` = 0 as logger will reset all previous messages when `size` > 0 during log rotation.

## TODO:
 
 - [ ] Unit tests
 - [ ] Add samples, project structure
 - [ ] Stack trace
 - [ ] Local/UTC timestamp (log file only)