#!c:\\python27\python.exe
# -*- coding: utf-8 -*-
# pylint: disable=E1101
# pylint: disable=F0401
# pylint: disable=C0103

'''This file contains all classes related to parsing and highlighting.'''

from PySide import QtGui, QtCore
import clang.cindex
import idaapi
import hrdev_plugin.include.helper
idaapi.require('hrdev_plugin.include.helper')


class Parser(object):
    '''Implements parser to parse Hex-Rays decompiler output.'''

    def __init__(self, plugin):
        super(Parser, self).__init__()
        self.plugin = plugin
        self.config_main = self.plugin.config_main
        self.gui = self.plugin.gui
        self.tools = self.plugin.tools

        self._token_kinds = hrdev_plugin.include.helper.AttributeDict()
        self._token_kinds.punctiation = []
        self._token_kinds.kkeyword = []
        self._token_kinds.identifier = []
        self._token_kinds.literal = []
        self._token_kinds.comment = []
        self._token_kinds.imported_functions = []
        self._token_kinds.banned_functions = []

        self._replacer_literal = None

        self._tab_width = self.config_main.getint('editor', 'tab_width')
        self._padding = "\t"
        if self.config_main.getboolean('editor', 'use_spaces'):
            self._padding = ' ' * self._tab_width
        return

    def run(self, file_name):
        '''Entry point.'''

        index = clang.cindex.Index.create()
        translation_unit = index.parse(file_name, ['-x', 'c++'])

        if self.config_main.getboolean('etc', 'verbose'):
            diagnostics = list(translation_unit.diagnostics)
            if len(diagnostics) > 0:
                print 'HRDEV: Found some Clang parse errors...'
                for diag in diagnostics:
                    print 'HRDEV: {}'.format(diag)
                print
        self._get_info(translation_unit.cursor)
        return

    def _collect_tokens(self, token):
        '''Collect tokens from parser output.'''

        if token.kind == clang.cindex.TokenKind.PUNCTUATION:
            if token.spelling not in self._token_kinds.punctiation:
                self._token_kinds.punctiation.append(token.spelling)

        elif token.kind == clang.cindex.TokenKind.KEYWORD:
            if token.spelling not in self._token_kinds.kkeyword:
                self._token_kinds.kkeyword.append(token.spelling)

        elif token.kind == clang.cindex.TokenKind.IDENTIFIER:

            if self.config_main.getboolean('editor', 'highlight_imports') \
               and token.spelling in self.plugin.imports:
                self._token_kinds.imported_functions.append(token.spelling)

            elif self.config_main.getboolean('editor', 'highlight_banned') \
               and token.spelling in self.plugin.banned_functions:
                self._token_kinds.banned_functions.append(token.spelling)

            elif token.spelling not in self._token_kinds.identifier:
                self._token_kinds.identifier.append(token.spelling)

        elif token.kind == clang.cindex.TokenKind.LITERAL:
            self._replacer_literal = token.spelling
            # Replace integers with hex format
            if self.config_main.getboolean('editor', 'all_numbers_in_hex'):
                idaapi.msg("{}".format(token.spelling))
                if self.tools.is_number(token.spelling):
                    self._replacer_literal = self.tools.to_hex(token.spelling)
            if token.spelling not in self._token_kinds.literal:
                self._token_kinds.literal.append(self._replacer_literal)

        elif token.kind == clang.cindex.TokenKind.COMMENT:
            if token.spelling not in self._token_kinds.comment:
                self._token_kinds.comment.append(token.spelling)
        return

    def _get_token(self, token, next_token):
        '''Get token and relevant information.'''

        self._collect_tokens(token)

        token_spelling = token.spelling
        if self._replacer_literal:
            token_spelling = self._replacer_literal
            self._replacer_literal = None

        if not next_token:
            self.gui.add_text(token_spelling)
            return

        if next_token.extent.start.line > token.extent.start.line:
            diff = next_token.extent.start.line - token.extent.start.line
            tail = ("\n" * diff) + \
                   ((next_token.extent.start.column - 1) /
                    self._tab_width) * self._padding
        else:
            diff = next_token.extent.start.column - token.extent.end.column
            tail = ' ' * diff

        buff = token_spelling + tail
        self.gui.add_text(buff)
        return

    def _get_base_info(self, node):
        '''Get base info.'''

        iteration = 0
        current = None
        for next_token in node.get_tokens():
            iteration += 1
            if iteration == 1:
                current = next_token
                continue
            self._get_token(current, next_token)
            current = next_token
        self._get_token(current, None)
        return

    def _get_info(self, node):
        '''Get info about node.'''

        self._get_base_info(node)
        self.gui.highlight_document(self._token_kinds)
        self.gui.set_loaded(True)
        return


class Highlighter(QtGui.QSyntaxHighlighter):
    '''Implements C/C++ syntax highligher.'''
    def __init__(self, parent, config_theme, keywords):
        super(Highlighter, self).__init__(parent)

        self.config_theme = config_theme
        self.keywords = keywords
        self._highlighting_rules = []
        self._create_rules()
        return

    def _create_rules(self):
        '''Create highlighting rules.'''

        # Identifiers
        identifier_format = QtGui.QTextCharFormat()
        foreground = QtGui.QColor(self.config_theme.get('tokens_highlight',
                                                        'identifier_color'))
        identifier_format.setForeground(foreground)
        for word in self.keywords.identifier:
            rule = QtCore.QRegExp('\\b{}\\b'.format(word))
            self._highlighting_rules.append((rule, identifier_format))

        # Special Identifier case for imported functions
        identifier_format = QtGui.QTextCharFormat()
        foreground = QtGui.QColor(self.config_theme.get('tokens_highlight',
                                                        'import_color'))
        identifier_format.setForeground(foreground)
        for word in self.keywords.imported_functions:
            rule = QtCore.QRegExp('\\b{}\\b'.format(word))
            self._highlighting_rules.append((rule, identifier_format))

        # Special Identifier case for banned functions
        identifier_format = QtGui.QTextCharFormat()
        foreground = QtGui.QColor(self.config_theme.get('tokens_highlight',
                                                        'banned_color'))
        identifier_format.setForeground(foreground)
        for word in self.keywords.banned_functions:
            rule = QtCore.QRegExp('\\b{}\\b'.format(word))
            self._highlighting_rules.append((rule, identifier_format))

        # Keywords
        keyword_format = QtGui.QTextCharFormat()
        foreground = QtGui.QColor(self.config_theme.get('tokens_highlight',
                                                        'keyword_color'))
        keyword_format.setForeground(foreground)
        keyword_format.setFontWeight(QtGui.QFont.Bold)
        for word in self.keywords.kkeyword:
            rule = QtCore.QRegExp('\\b{}\\b'.format(word))
            self._highlighting_rules.append((rule, keyword_format))

        # Literals
        literal_format = QtGui.QTextCharFormat()
        foreground = QtGui.QColor(self.config_theme.get('tokens_highlight',
                                                        'literal_color'))
        literal_format.setForeground(foreground)
        for word in self.keywords.literal:
            rule = QtCore.QRegExp('\\b{}\\b'.format(word))
            self._highlighting_rules.append((rule, literal_format))

        # Comments
        comment_format = QtGui.QTextCharFormat()
        foreground = QtGui.QColor(self.config_theme.get('tokens_highlight',
                                                        'comment_color'))
        comment_format.setForeground(foreground)
        rule = QtCore.QRegExp('//[^\n]*')
        self._highlighting_rules.append((rule, comment_format))

        # Quotation
        quotation_format = QtGui.QTextCharFormat()
        foreground = QtGui.QColor(self.config_theme.get('tokens_highlight',
                                                        'quotation_color'))
        quotation_format.setForeground(foreground)
        rule = QtCore.QRegExp('".*"')
        self._highlighting_rules.append((rule, quotation_format))

        self.comment_start_expression = QtCore.QRegExp('/\\*')
        self.comment_end_expression = QtCore.QRegExp('\\*/')
        return

    def highlightBlock(self, text):
        '''Highlight block.'''

        for pattern, hl_format in self._highlighting_rules:
            expression = QtCore.QRegExp(pattern)
            index = expression.indexIn(text)
            while index >= 0:
                length = expression.matchedLength()
                self.setFormat(index, length, hl_format)
                index = expression.indexIn(text, index + length)

        self.setCurrentBlockState(0)

        start_index = 0
        if self.previousBlockState() != 1:
            start_index = self.comment_start_expression.indexIn(text)

        while start_index >= 0:
            end_index = self.comment_end_expression.indexIn(text, start_index)

            if end_index == -1:
                self.setCurrentBlockState(1)
                comment_length = text.length() - start_index
            else:
                comment_length = end_index - \
                                 start_index + \
                                 self.comment_end_expression.matchedLength()

            multi_line_comment_format = QtGui.QTextCharFormat()
            multiline_color = self.config_theme.get('tokens_highlight',
                                                    'quotation_color')
            multi_line_comment_format.setForeground(QtGui.QColor(multiline_color))
            self.setFormat(start_index, comment_length,
                           multi_line_comment_format)
            start_index = self.comment_start_expression.indexIn(text,
                                                                start_index +
                                                                comment_length)
        return
