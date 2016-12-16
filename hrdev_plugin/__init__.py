#!c:\\python27\python.exe
# -*- coding: utf-8 -*-
# pylint: disable=E1101
# pylint: disable=F0401

'''
Hex-Rays Decompiler Enhanced View plugin (HRDEV).

This is a simple plugin to view somewhat enhanced decompiler output. For
more information check out github: https://github.com/ax330d/hrdev/.
'''

import re
import os
import ConfigParser

try:
    from PySide import QtCore, QtGui
except:
    from PyQt5 import QtCore, QtWidgets

import idaapi
import idc
import tempfile

try:
    import hrdev_plugin.include.syntax
    import hrdev_plugin.include.gui
    import hrdev_plugin.include.helper

    idaapi.require('hrdev_plugin.include.syntax')
    idaapi.require('hrdev_plugin.include.gui')
    idaapi.require('hrdev_plugin.include.helper')
except Exception, e:
    print e

class Plugin(object):
    '''Implements the main plugin class, entry point.'''

    def __init__(self):
        super(Plugin, self).__init__()

        self.tools = hrdev_plugin.include.helper.Tools(self)
        self.config_main = ConfigParser.ConfigParser()
        self.config_theme = ConfigParser.ConfigParser()

        self._bin_md5 = idc.GetInputMD5()
        self._bin_name = re.sub(r'\.[^.]*$', '', idc.GetInputFile())

        self.imports = self._get_imported_names()
        self.tmp_items = []
        real_dir = os.path.realpath(__file__).split('\\')
        real_dir.pop()
        real_dir = os.path.sep.join(real_dir)

        self._read_config(real_dir)
        self.banned_functions = \
            self.config_main.get('etc', 'banned_functions').split(',')
        self.gui = None
        self.parser = None

    def _imports_names_cb(self, eaddr, name, ordinal):
        '''Callback for enumeration.'''
        self.tmp_items.append('' if not name else name)
        # True -> Continue enumeration
        return True

    def _build_imports(self):
        '''Build imports table. (Was taken from examples.)'''

        tree = {}
        nimps = idaapi.get_import_module_qty()

        for i in xrange(0, nimps):
            name = idaapi.get_import_module_name(i)
            if not name:
                continue
            # Create a list for imported names
            self.tmp_items = []

            # Enum imported entries in this module
            idaapi.enum_import_names(i, self._imports_names_cb)

            if name not in tree:
                tree[name] = []
            tree[name].extend(self.tmp_items)

        return tree

    def _get_imported_names(self):
        '''Create and return a list of imported function names.'''

        tmp = []
        for _, imp_entries in self._build_imports().items():
            for imp_name in imp_entries:
                tmp_name = idc.Demangle(imp_name, idc.GetLongPrm(idc.INF_SHORT_DN))
                if tmp_name:
                    imp_name = tmp_name
                tmp.append(imp_name)
        return tmp

    def _read_config(self, real_dir):
        '''Read config and initialise variables.'''

        dir_chunks = real_dir.split(os.path.sep)
        dir_chunks.pop()

        self.current_dir = os.path.sep.join(dir_chunks)
        config_path = os.path.sep.join([self.current_dir, 'hrdev_plugin',
                                        'data', 'config.ini'])
        self.config_main.read(config_path)
        theme_name = str(self.config_main.get('editor', 'highlight_theme'))

        theme_config_path = os.path.sep.join([self.current_dir, 'hrdev_plugin',
                                              'data', 'themes',
                                              '{}.ini'.format(theme_name)])
        self.config_theme.read(theme_config_path)
        return

    def run(self):
        '''Start the plugin.'''

        if not idaapi.init_hexrays_plugin():
            print "HRDEV Error: Failed to initialise Hex-Rays plugin."
            return

        function_name = idaapi.get_func_name(idaapi.get_screen_ea())
        demangled_name = self.tools.demangle_name(function_name)

        src = idaapi.decompile(idaapi.get_screen_ea())

        file_name = '{}.cpp'.format(self.tools.to_file_name(demangled_name))
        cache_path = os.path.sep.join([tempfile.gettempdir(),
                                       'hrdev_cache',
                                       self._bin_name])

        # Create required directories if they dont exist
        tmp_dir_path = os.path.sep.join([tempfile.gettempdir(), 'hrdev_cache'])
        if not os.path.isdir(tmp_dir_path):
            os.mkdir(tmp_dir_path)

        if not os.path.isdir(cache_path):
            os.mkdir(cache_path)

        complete_path = os.path.sep.join([cache_path, file_name])
        idaapi.msg("HRDEV cache path: {}\n".format(complete_path))

        # Check if file is already in cache
        if not os.path.isfile(complete_path) or \
           self.config_main.getboolean('etc', 'disable_cache'):
            self.tools.save_file(complete_path, str(src))

        self.tools.set_file_path(complete_path)

        lvars = {}
        for v in src.lvars:
            _type = idaapi.print_tinfo('', 0, 0, idaapi.PRTYPE_1LINE, v.tif, '', '')
            lvars[str(v.name)] = "{} {} {}".\
                format(_type, str(v.name), str(v.cmt))

        max_title = self.config_main.getint('etc', 'max_title')
        self.gui = hrdev_plugin.include.gui.Canvas(self.config_main,
                                                   self.config_theme,
                                                   self.tools,
                                                   lvars,
                                                   demangled_name[:max_title])
        self.gui.Show('HRDEV')

        self.parser = hrdev_plugin.include.syntax.Parser(self, lvars)
        self.parser.run(complete_path)
        return
