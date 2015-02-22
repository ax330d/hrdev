#!c:\\python27\python.exe
# -*- coding: utf-8 -*-
# pylint: disable=F0401

'''This file contains LNTextEdit class which represents overloaded
QPlainTextEdit with some basic editor features.
'''

import re

import idc


class AttributeDict(dict):
    '''Implements access to dictionary elements through dot.'''
    def __getattr__(self, attr):
        return self[attr]

    def __setattr__(self, attr, value):
        self[attr] = value


class Tools(object):
    '''Implements container for various helper functions.'''
    def __init__(self, plugin):
        super(Tools, self).__init__()
        self._plugin = plugin
        self._last_file_name = None
        return

    @classmethod
    def demangle_name(cls, name):
        '''Demangle name.'''
        tmp = idc.Demangle(name, idc.GetLongPrm(idc.INF_SHORT_DN))
        if tmp:
            name = tmp
        matches = re.match(r'^(.*?)\(.*?\)', name)
        if matches:
            name = matches.group(1)
        return name

    def to_file_name(self, demangle_name):
        '''Convert text to safe file name.'''
        replacers = {
            '\\': '_',
            '/': '_',
            ':': '_',
            '*': '_',
            '?': '_',
            '"': '_',
            '<': '_',
            '>': '_',
            '|': '_'
        }
        return self.replace(demangle_name, replacers)

    def save_file(self, file_name=None, data=None):
        '''Save file.'''
        if not file_name:
            file_name = self._last_file_name
        with open(file_name, 'w') as fout:
            fout.write(data)
        if bool(self._plugin.config_main.get('etc', 'verbose')):
            print 'HRDEV: Saved data to {}'.format(file_name)
        return

    def set_file_path(self, file_name):
        '''Set path to data.'''
        self._last_file_name = file_name
        return

    @classmethod
    def replace(cls, text, dic):
        '''Replace all matches in the text.'''
        for i, j in dic.iteritems():
            text = text.replace(i, j)
        return text

    @classmethod
    def get_type(cls, function):
        '''Get function type.'''
        ctype = idc.GetType(function)
        if not ctype:
            ctype = idc.GuessType(function)
            if not ctype:
                ctype = ''
        return ctype

    @classmethod
    def get_addr_from_name(cls, name):
        '''Return function address by its name.'''
        return idc.LocByNameEx(idc.here(), name)

    @classmethod
    def to_hex(cls, number):
        '''Convert anything to hex.'''

        number = number.replace('u', '')
        if number[:2] == '0x':
            return number
        try:
            number = hex(int(number, 0))
        except TypeError:
            pass
        return number

    @classmethod
    def to_number(cls, number):
        '''Convert anything to number.'''
        try:
            number = int(number, 0)
        except TypeError:
            pass
        return number

    @classmethod
    def get_tabs(cls, text):
        '''Count tabs in block text.'''

        matches = re.match(r'(\s+)(.*?)', text)
        if matches:
            return matches.group(1).count(' ')
        return 0
