#!c:\\python27\python.exe
# -*- coding: utf-8 -*-

'''This file contains all classes related to parsing and highlighting.'''

try:
    from PySide import QtCore, QtGui
except:
    from PyQt5 import QtCore, QtGui

import clang.cindex
import idaapi
import hrdev_plugin.include.helper
idaapi.require('hrdev_plugin.include.helper')


class Parser(object):
    '''Implements parser to parse Hex-Rays decompiler output.'''

    def __init__(self, plugin, lvars):
        super(Parser, self).__init__()
        self.plugin = plugin
        self.lvars = lvars
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
        self._formatting_context = hrdev_plugin.include.helper.AttributeDict()
        self._formatting_context.opened_brackets = 0
        self._formatting_context.closed_brackets = 0
        self._formatting_context.last_indent_num = 0
        self._formatting_context.newline_started = False
        self._formatting_context.prev_is_label = False
        self._formatting_context.prev_is_case = False
        self._formatting_context.curr_in_case = False

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

        self.gui.add_text(self._format_pre(token, next_token) +
                          token_spelling +
                          self._format_post(token, next_token))
        return

    def _format_pre(self, token, next_token):
        '''Add spacing depending before on current keyword.'''

        if token.spelling == ':':
            return ''

        if token.spelling == '{':
            self._formatting_context.opened_brackets += 1
            self._formatting_context.last_indent_num += 1
            return self._get_tabs() + ''

        if token.spelling == '}':
            self._formatting_context.closed_brackets += 1
            if self._formatting_context.closed_brackets == \
               self._formatting_context.opened_brackets:
                self._formatting_context.closed_brackets -= 1
                self._formatting_context.opened_brackets -= 1
            self._formatting_context.last_indent_num -= 1
            self._formatting_context.newline_started = True
            return self._get_tabs() + ''

        if token.spelling[0:5] == 'LABEL' and next_token.spelling == ':':
            return ''

        return self._get_tabs() + ''

    def _format_post(self, token, next_token):
        '''Add spacing after depending on current and next keyword.'''

        if token.spelling[0:5] == 'LABEL' and next_token.spelling == ':':
            self._formatting_context.prev_is_label = True
            return ''

        if self._formatting_context.prev_is_label:
            self._formatting_context.prev_is_label = False
            return '\n'

        if token.spelling == ';' and next_token.spelling == 'case':
            self._formatting_context.last_indent_num -= 1
            self._formatting_context.newline_started = True
            return '\n'

        if token.spelling == 'case' and token.kind == clang.cindex.TokenKind.KEYWORD:
            self._formatting_context.prev_is_case = True
            self._formatting_context.curr_in_case = True
            return ' '

        if token.spelling == ':' and self._formatting_context.prev_is_case:
            self._formatting_context.last_indent_num += 1
            self._formatting_context.prev_is_case = False
            self._formatting_context.newline_started = True
            return '\n'

        # Handle "case xxx:"
        if next_token.spelling == ':' and self._formatting_context.prev_is_case:
            return ''

        # Handle "xxx; // comment"
        if token.spelling == ';' and next_token.kind == clang.cindex.TokenKind.COMMENT:
            return ' '

        # Handle " & 0x7fffffff"
        if token.spelling == '&' and next_token.kind == clang.cindex.TokenKind.LITERAL:
            return ' '

        if next_token.spelling == '}' and self._formatting_context.curr_in_case:
            self._formatting_context.curr_in_case = False
            self._formatting_context.last_indent_num -= 1
            self._formatting_context.newline_started = True
            return '\n'

        if token.spelling == '}' and next_token.spelling == 'else':
            return ' '

        if self._is_newline_spelling(token.spelling) or \
           token.kind == clang.cindex.TokenKind.COMMENT:
            self._formatting_context.newline_started = True
            return '\n'

        # Handle left and right sides no-space tokens
        if self._is_nospace_token(token.spelling) or \
           self._is_nospace_token(next_token.spelling):
            return ''

        # Handle only right-space tokens (a, b, c, ...)
        if next_token.spelling in [',', ')', ']', ';']:
            return ''

        # Handle only left-space tokens (,a ,b ,c ,...)
        if token.spelling in ['(', '&', '*']:
            return ''

        # Increment/decrement operators
        if token.spelling in ['--', '++'] and \
           next_token.kind == clang.cindex.TokenKind.IDENTIFIER:
            return ''
        if next_token.spelling in ['--', '++'] and \
           token.kind == clang.cindex.TokenKind.IDENTIFIER:
            return ''

        # Function calls
        if next_token.spelling == '(' and \
           token.kind == clang.cindex.TokenKind.IDENTIFIER:
            return ''

        return ' '

    def _get_tabs(self):
        '''Returns necessary amount of tabs.'''
        tabs = ''
        if self._formatting_context.newline_started:
            tabs = self._padding * \
                   self._formatting_context.last_indent_num
            self._formatting_context.newline_started = False
        return tabs

    def _is_nospace_token(self, token_spelling):
        tokens = ['.', '->', '[', '!', '::', '~']
        return token_spelling in tokens

    def _is_newline_spelling(self, token_spelling):
        newlines = ['{', '}', ';']
        return token_spelling in newlines

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
