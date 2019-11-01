# extract_time_blk_bz2_py

The main reason for this project was to learn Python.
Previously, I've spent a lot of time on learning how bzip2 works doing my previous C project with the same [name](https://github.com/eugenyuk/extract_time_blk_bz2). I've decided to do the same in Python. As a result, it works much slower (as expected) than C version.

This tool is useful when you need to get a part of a huge (hundreds of gigabytes) log file which was compressed with bzip2.
It finds and extracts only bz2 blocks, which contain a data between --from and --to timestamps in a log.

How to use a tool:
```sh
> extract_time_blk_bz2.py --from="datetime" --to="datetime" --file="/full/path/to/file.bz2"
```
Supported from/to datetime formats are:

    "%Y-%m-%dT%H:%M:%S" (Ex. "2017-02-21T14:53:22")
    "%b %d %H:%M:%S" (Ex. "Oct 30 05:54:01")
    "%Y-%m-%d %H:%M:%S" (Ex. "2017-02-21 14:53:22")
    "%d/%b/%Y:%H:%M:%S" (Ex. "12/Dec/2015:18:39:27")

Tool was successfully tested on the following platforms:

Linux Fedora 30 x64

Windows 10 x64

TODO:
implement multi processing module to speed up program execution
