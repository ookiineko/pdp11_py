# pdp11_py

*exact* Python port of the PDP-11 emulator written in Javascript and HTML from http://pdp11.aiju.de/

## what is about this port

this port works and i made it using my free time in 2 days

it's very hacky and buggy and may have some weird Python quirks (and maybe some typos)

code modification is minimal, so don't except clean code like [PyPDP11](https://github.com/amakukha/PyPDP11)

code structure, comments, function/variable name, almost everything, are the same

no GUI, terminal only for now (but if u want u can try to add TUI using ncurses or sth xd)

## tested features

 - booting kernel
 - backspace, del line
 - setting lowercase tty
 - terminate program
 - running ls and ed
 - compiling and running c, asm programs

## host requirement

python3.11, lower is not tested, but u can fix that easily i think

## tested platform

only tested on linux (amd64) with python3.11

should also work on other archs and unixs, like macos and cygwin

## credits

```text
(c) 2011 Julius Schmidt, JavaScript implementation, MIT License
(c) 2023 Ookiineko, ported to Python 3, MIT License
Version 6 Unix (in the disk image) is available under the four-clause BSD license.
```

## see also

[PyPDP11](https://github.com/amakukha/PyPDP11): another Python 3 port with tkinter based GUI and some extra features like hostfs and saving/loading disk image.

## finally

good luck and have fun xd
