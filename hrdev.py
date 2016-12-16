#!c:\\python27\python.exe
# -*- coding: utf-8 -*-

'''Just a wrapper module.'''

import idaapi
from hrdev_plugin import Plugin

try:
    from PySide import QtCore, QtGui
except:
    from PyQt5 import QtCore, QtWidgets


__author__ = 'Arthur Gerkis'
__version__ = '0.0.4 (beta)'


class HRDEVPluginEntry(idaapi.plugin_t):
    '''HRDEV Plugin Entry.'''
    flags = idaapi.PLUGIN_UNL
    comment = "Hex-Rays Decompiler Enhanced View"

    help = ""
    wanted_name = "HRDEV"
    wanted_hotkey = "Alt+F5"

    def init(self):
        print "HRDEV plugin is loaded. Use Alt+F5 hotkey to decompile."
        return idaapi.PLUGIN_OK

    def run(self, arg):
        Plugin().run()

    def term(self):
        return


class HRDEVMenuHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        Plugin().run()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


idaapi.register_action(idaapi.action_desc_t(
    'hrdev:decompile',
    'Generate pseudocode (HRDEV)',
    HRDEVMenuHandler(),
    'Alt+F5',
    'Generate pseudocode (HRDEV)'))


idaapi.attach_action_to_menu(
    'View/Open subviews/Generate pseudocode',
    'hrdev:decompile',
    idaapi.SETMENU_APP)


def PLUGIN_ENTRY():
    return HRDEVPluginEntry()
