Hex-Rays Decompiler Enhanced View (HRDEV)
-----------------------------------------

### What is this

This is a simple IDA Pro Python plugin to make Hex-Rays Decompiler output bit
more attractive. HRDEV plugin retrieves standard decompiler output, parses it
with Python Clang bindings, does some magic, and puts back.


### How it works

Load plugin, then press "Alt + ," and listing will appear. Currently this is an
alternative only to a standard "Alt + F5" (function decompilation), listing for
complete files is currently not supported.

As this plugin is written in Python, parsing huge file may be time consuming,
so it probably makes no sense to support complete file parsing.

### Requirements

The only requirement is Clang Python binding. See https://pypi.python.org/pypi/clang.
Clang binding is required to parse decompiler output and produce plugin output.


### Installing

First install Clang Python binding, then just paste plugin into "plugins/" IDA
folder and it will be available on startup.

### Options

HRDEV plugin has following key shortcuts:

 * Ctr+S - will save current document
 * Ctr+F - will pop up find-replace modal dialog

HRDEV plugin comes with several themes for syntax highlighting, however, you
can edit them or add own. To add your own, simply paste file with certain theme
name to folder "data/themes" and edit your file. The name of the file is the
name of the theme.

For various editor options please take a look at "data/config.ini" and
configuration files in "data/themes/\*.ini". Files contain comments, so it should
not be difficult to understand how to configure editor.

You can toggle line highlight on-off by clicking twice on line number bar.


### Other things to know

Please note that Hex-Rays decompiler tabulation width has to match with plugin
tabulation width setting, otherwise you get ugly indentation.

Plugin may print that there were some Clang parsing errors, but normally that is
not of a big concern, usually you can ignore them.

Plugin saves all decompiled files to the "hrdev_cache/MODULE_NAME/\*" temporary
folder. It is done so you can save changes made to file. Next time when Alt+,
is pressed, plugin will lookup for file in cache. If you want to discard changes
made, simply delete file in "hrdev_cache/MODULE_NAME/\*" folder.

This is still beta-release, so I am pretty sure you will find some bugs. Don't
hesitate to report them.

Plugin was tested on Windows only, however, I believe that there should be no
problems on other platforms.


### Examples

This is how usually output looks like:

![Decompiler outut](https://github.com/ax330d/hrdev/raw/master/hrdev_plugin/docs/images/std-view.png "Standard Hex-Rays Decompiler output")

This is how output looks by plugin:

![Enhanced View](https://github.com/ax330d/hrdev/raw/master/hrdev_plugin/docs/images/plg-view.png "Plugin output")


### TODOs

 * toggle casts
 * add menu like in original output

Work is still ongoing, and please, make feature requests!
