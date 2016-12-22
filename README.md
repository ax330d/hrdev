Hex-Rays Decompiler Enhanced View (HRDEV)
-----------------------------------------

### What is this

This is an IDA Pro Python plugin to make Hex-Rays Decompiler output bit more
attractive. HRDEV plugin retrieves standard decompiler output, parses it with
Python Clang bindings and puts back.


### Requirements & installation

The only requirement is Clang Python binding. See https://pypi.python.org/pypi/clang.
Clang binding is required to parse decompiler output and produce plugin output.

First install Clang Python binding if you don't have it, then just paste plugin
into "plugins/" IDA folder and plugin will be available on startup.

Note: please make sure that you have matching LLVM Python bindings and
LLVM version installed (http://releases.llvm.org/download.html).
Otherwise you may get errors due to incompatibility. This is not an
HRDEV issue.  

Note: only IDA version higher than 6.6 is supported. If I get requests
to support earlier versions I will port HRDEV. See http://www.hexblog.com/?p=886.


### How it works

Load plugin, then press "Alt + F5" and listing will appear. Currently this is an
alternative only to a standard "F5" (function decompilation), listing for
complete files is currently not supported.

You can put plugin into "plugins/" directory or load it via Alt+F7. If
you put it into "plugins/" folder, then place hrdev.py and hrdev_plugin
at the same level and exactly under "plugins/".

### Options

HRDEV plugin has other key shortcuts:

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

Plugin may print that there were some Clang parsing errors, but normally that is
not of a big concern, usually you can ignore them.

Plugin saves all decompiled files to the "hrdev_cache/MODULE_NAME/\*" temporary
folder. It is done so you can save changes made to file. Next time when Alt+F5,
is pressed, plugin will lookup for file in cache. If you want to discard changes
made, simply delete file in "hrdev_cache/MODULE_NAME/\*" folder or disable file
caching at all by configuring settings: "disable_cache=True".

This is still beta-release, so I am pretty sure you will find some bugs. Don't
hesitate to report them.

Plugin was tested on Windows only, however, I believe that there should be no
problems on other platforms.

Parsing huge file may take a while.

### Examples

This is how usually output looks like:

![Decompiler outut](https://github.com/ax330d/hrdev/raw/master/hrdev_plugin/docs/images/std-view.png "Standard Hex-Rays Decompiler output")

This is how output looks by plugin:

![Enhanced View](https://github.com/ax330d/hrdev/raw/master/hrdev_plugin/docs/images/plg-view.png "Plugin output")


### TODOs and bugs

See TODO.
