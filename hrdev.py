#!c:\\python27\python.exe
# -*- coding: utf-8 -*-

'''Just a wrapper module.'''

import os

import idaapi
from hrdev_plugin import Plugin
from PySide import QtCore, QtGui

__author__ = 'Arthur Gerkis'
__version__ = '0.0.3 (beta)'


class hrdevplugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Hex-Rays Decompiler Enhanced View"

    help = "Nothing here"
    wanted_name = "HRDEV"
    wanted_hotkey = "Alt-,"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        Plugin().run()

    def term(self):
        return


def PLUGIN_ENTRY():
    return hrdevplugin_t()
