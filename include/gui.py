#!c:\\python27\python.exe
# -*- coding: utf-8 -*-
# pylint: disable=F0401
# pylint: disable=E1101
# pylint: disable=C0103

'''This file contains all classes related to the user interface.'''


import re
from PySide import QtCore, QtGui
from PySide.QtCore import QRect
from PySide.QtCore import Qt
from PySide.QtGui import QFrame
from PySide.QtGui import QHBoxLayout
from PySide.QtGui import QPainter
from PySide.QtGui import QPlainTextEdit
from PySide.QtGui import QTextFormat
from PySide.QtGui import QWidget
from PySide.QtGui import QTextEdit

import idaapi
import include.syntax
import include.helper

idaapi.require('include.syntax')
idaapi.require('include.helper')


class LNTextEdit(QFrame):
    '''Redefined QPLainTextEditor with additional features.'''

    class NumberBar(QWidget):
        '''Number bar class.'''

        def __init__(self, config_theme, edit):

            QWidget.__init__(self, edit)

            self.config_theme = config_theme
            self.edit = edit

            self.breakpoints = {}

            self.adjust_width(3)
            self.setStyleSheet(
                'background-color:{}; color: {};'.
                format(self.config_theme.get('number_bar', 'background_color'),
                       self.config_theme.get('number_bar', 'font_color')))

            font_name = self.config_theme.get('number_bar', 'font_name')
            font_size = self.config_theme.getint('number_bar', 'font_size')
            font = QtGui.QFont(font_name, font_size, QtGui.QFont.Light)
            self.setFont(font)
            return

        def mouseDoubleClickEvent(self, event):
            '''Handle mouse double click event.'''

            y = self._get_y(event.pos())
            cursor = self.edit.cursorForPosition(QtCore.QPoint(0, y))
            clicked_line = cursor.blockNumber() + 1
            self._toogle_breakpoint(cursor, clicked_line)
            return

        def paintEvent(self, event):
            '''Handle paint event.'''

            self._numberbar_paint(self, event)
            QWidget.paintEvent(self, event)
            return

        def _get_y(self, pos):
            '''Get Y coordinate.'''
            tmp = self.mapToGlobal(pos)
            return self.edit.viewport().mapFromGlobal(tmp).y()

        def _toogle_breakpoint(self, cursor, line_number):
            '''Toggle breakpoint line.'''

            if line_number in self.breakpoints:
                self.breakpoints[line_number].cursor.clearSelection()
                self.breakpoints.pop(line_number)
                selections = []
                for prev_selection in self.breakpoints:
                    selections.append(self.breakpoints[prev_selection])
                self.edit.setExtraSelections(selections)
                return

            color = self.config_theme.get('editor', 'breakpoint_line_color')

            selection = QTextEdit.ExtraSelection()
            selection.format.setBackground(QtGui.QColor(color))
            selection.format.setProperty(QTextFormat.FullWidthSelection, True)
            selection.cursor = cursor

            self.breakpoints[line_number] = selection

            selections = []
            for prev_selection in self.breakpoints:
                selections.append(self.breakpoints[prev_selection])
            selections.append(selection)

            self.edit.setExtraSelections(selections)
            return

        def _numberbar_paint(self, number_bar, event):
            '''Paint number bar.'''

            font_metrics = self.fontMetrics()
            current_line = self.edit.document().findBlock(
                self.edit.textCursor().position()
            ).blockNumber() + 1

            block = self.edit.firstVisibleBlock()
            line_count = block.blockNumber()
            painter = QPainter(number_bar)
            painter.fillRect(event.rect(), self.palette().base())

            # Iterate over all visible text blocks in the document.
            while block.isValid():
                line_count += 1
                block_top = self.edit.blockBoundingGeometry(block).\
                    translated(self.edit.contentOffset()).top()

                # Check if the position of the block is out side of the visible
                # area.
                if not block.isVisible() or block_top >= event.rect().bottom():
                    break

                # We want the line number for the selected line to be bold.
                if line_count == current_line:
                    font = painter.font()
                    font.setBold(True)
                    font.setUnderline(True)
                    painter.setFont(font)
                else:
                    font = painter.font()
                    font.setBold(False)
                    font.setUnderline(False)
                    painter.setFont(font)

                # Draw the line number right justified at the position of the
                # line.
                paint_rect = QRect(0, block_top, number_bar.width(),
                                   font_metrics.height())
                painter.drawText(paint_rect, Qt.AlignRight,
                                 "{} ".format(unicode(line_count)))

                block = block.next()

            painter.end()
            return

        def adjust_width(self, count):
            '''Adjust number bar width.'''

            width = self.fontMetrics().width(unicode(count))
            if self.width() != width:
                self.setFixedWidth(width + 10)
            return

        def update_contents(self, rect, scroll):
            '''Update contents of number bar.'''

            if scroll:
                self.scroll(0, scroll)
            else:
                # It would be nice to do
                # self.update(0, rect.y(), self.width(), rect.height())
                # But we can't because it will not remove the bold on the
                # current line if word wrap is enabled and a new block is
                # selected.
                self.update()
            return

    class PlainTextEdit(QPlainTextEdit):
        '''PlainTextEdit Class.'''

        def __init__(self, parent, *args):

            QPlainTextEdit.__init__(self, *args)
            self.parent = parent
            self.config_main = self.parent.config_main
            self.config_theme = self.parent.config_theme
            self.tools = self.parent.tools

            self._loaded = False

            self.setFrameStyle(QFrame.NoFrame)
            self.setLineWrapMode(QPlainTextEdit.NoWrap)

            self._setup_ui()

            self._casts_marked = False
            self._casts_selections = None

            self.cursorPositionChanged.connect(
                self._on_cursor_position_changed)

            self._bracket_info = include.helper.AttributeDict()
            self._bracket_info.saved_bracket = None
            self._bracket_info.depth = 0
            self._bracket_info.seeking_nl = False
            self._bracket_info.open_brackets = ['[', '{', '(']
            self._bracket_info.closed_brackets = [']', '}', ')']
            self._bracket_info.pairs_closed = {']': '[', '}': '{', ')': '('}
            self._bracket_info.pairs_open = {'[': ']', '{': '}', '(': ')'}
            self._bracket_info.ignore_stack_left = []
            self._bracket_info.ignore_stack_right = []

            self._left_selected_bracket = QTextEdit.ExtraSelection()
            self._right_selected_bracket = QTextEdit.ExtraSelection()

            self._min_marker_len = self.config_main.getint('editor',
                                                           'min_marker_len')
            return

        def _setup_ui(self):
            '''Read configuration and apply rules.'''

            font_name = self.config_theme.get('editor', 'font_name')
            font_size = self.config_theme.getint('editor', 'font_size')
            font = QtGui.QFont(font_name, font_size, QtGui.QFont.Light)
            self.setFont(font)

            palette = self.palette()
            color = self.config_theme.get('editor', 'font_color')
            palette.setColor(QtGui.QPalette.Text, QtGui.QColor(color))
            self.setPalette(palette)
            return

        def paintEvent(self, event):
            '''Handle the paint event.'''

            super(QPlainTextEdit, self).paintEvent(event)

            self._highlight_indents(event)

            QPlainTextEdit.paintEvent(self, event)
            return

        def mouseDoubleClickEvent(self, event):
            '''TODO: Handle the double mouse click event.'''

            cursor = self.cursorForPosition(event.pos())
            cursor.select(QtGui.QTextCursor.WordUnderCursor)
            name = cursor.selectedText()
            if self.config_main.getboolean('editor', 'all_numbers_in_hex'):
                print 'HRDEV: {}'.format(self.tools.to_number(name))
            else:
                print 'HRDEV: {}'.format(self.tools.to_hex(name))
            # self._toggle_casts()
            return

        def _on_cursor_position_changed(self):
            '''Handle for cursorPositionChanged event.'''

            if not self._loaded:
                return

            # First add selection for toggled lines
            all_selections = []
            for ln in self.parent.number_bar.breakpoints:
                all_selections.append(self.parent.number_bar.breakpoints[ln])

            line_selection = self._watch_line()
            if line_selection:
                all_selections.append(line_selection)

            marker_selections = self._watch_marker()
            if marker_selections:
                all_selections.extend(marker_selections)

            self._watch_brackets()
            all_selections.append(self._left_selected_bracket)
            all_selections.append(self._right_selected_bracket)

            self.setExtraSelections(all_selections)
            return

        def _watch_line(self):
            '''Handler for current line change.'''

            selection = QTextEdit.ExtraSelection()
            color = self.config_theme.get('editor', 'current_line_color')
            selection.format.setBackground(QtGui.QColor(color))
            selection.format.setProperty(QTextFormat.FullWidthSelection, True)
            selection.cursor = self.textCursor()
            return selection

        def _watch_marker(self):
            '''Handler to create text markers.'''

            if not self.textCursor():
                return

            cursor = self.textCursor()
            cursor.select(QtGui.QTextCursor.WordUnderCursor)
            word = cursor.selectedText()
            if not word:
                return
            if len(word) < self._min_marker_len:
                return

            cursor.movePosition(QtGui.QTextCursor.Start)

            search_flag = QtGui.QTextDocument.FindFlags(0)
            search_flag |= QtGui.QTextDocument.FindWholeWords
            search_flag |= QtGui.QTextDocument.FindCaseSensitively

            selections = []
            marker_color = self.config_theme.get('editor', 'marker_color')

            selection = QTextEdit.ExtraSelection()
            selection.format.setBackground(QtGui.QColor(marker_color))
            selection.cursor = cursor
            selections.append(selection)

            while cursor:
                cursor = self.document().find(word, cursor, search_flag)
                if not cursor:
                    break
                selection = QTextEdit.ExtraSelection()
                selection.format.setBackground(QtGui.QColor(marker_color))
                selection.cursor = cursor
                selections.append(selection)
            return selections

        def _watch_brackets(self):
            '''Highlight brackets, parentheses.'''

            cursor = self.textCursor()

            self._left_selected_bracket.cursor.clearSelection()
            self._right_selected_bracket.cursor.clearSelection()

            block = cursor.block()

            cursor_position = cursor.position() - cursor.block().position()
            pos_left, pos_right = self._find_brackets(block, cursor_position)
            if not pos_left:
                return
            if not pos_right:
                return

            self._mark_brackets(cursor, pos_left, pos_right)
            return

        def _find_brackets(self, block, current_position):
            '''Seeks for brackets recursively.'''

            saved_block = block
            look_for = None
            data = block.text()
            l_current_position = current_position

            while block.isValid():
                chunks = list(data)
                l_block_position = block.position()

                found_left, position_left = \
                    self._find_brackets_left(chunks, l_current_position)
                if found_left:
                    look_for = self._bracket_info.pairs_open[
                        self._bracket_info.saved_bracket]
                    break
                block = block.previous()
                data = block.text()
                l_current_position = len(data)

            block = saved_block
            data = block.text()
            r_current_position = current_position

            while block.isValid():
                chunks = list(data)
                r_block_position = block.position()

                found_right, position_right = \
                    self._find_brackets_right(chunks, r_current_position)
                if self._bracket_info.saved_bracket == look_for:
                    break
                block = block.next()
                data = block.text()
                r_current_position = 0

            if not found_left and not found_right:
                return None, None

            return (l_block_position + l_current_position - position_left,
                    r_block_position + r_current_position + position_right)

        def _find_brackets_left(self, chunks, cursor_position):
            '''Find brackets from the left side.'''

            found_left = False
            position_left = 0

            for index in xrange(cursor_position - 1, -1, -1):
                char = chunks[index]
                position_left += 1
                if not char:
                    continue
                if char in self._bracket_info.closed_brackets:
                    opposite = self._bracket_info.pairs_closed[char]
                    self._bracket_info.ignore_stack_left.append(opposite)
                    continue

                if char in self._bracket_info.open_brackets:
                    if len(self._bracket_info.ignore_stack_left) and \
                       char == self._bracket_info.ignore_stack_left[-1]:
                        self._bracket_info.ignore_stack_left.pop()
                    else:
                        self._bracket_info.saved_bracket = char
                        found_left = True
                        break

            return found_left, position_left

        def _find_brackets_right(self, chunks, cursor_position):
            '''Find brackets from the right side.'''

            found_right = False
            position_right = 0

            for index in xrange(cursor_position, len(chunks)):
                char = chunks[index]
                position_right += 1
                if not char:
                    continue
                if char in self._bracket_info.open_brackets:
                    opposite = self._bracket_info.pairs_open[char]
                    self._bracket_info.ignore_stack_right.append(opposite)
                    continue

                if char in self._bracket_info.closed_brackets:
                    if len(self._bracket_info.ignore_stack_right) and \
                       char == self._bracket_info.ignore_stack_right[-1]:
                        self._bracket_info.ignore_stack_right.pop()
                    else:
                        self._bracket_info.saved_bracket = char
                        found_right = True
                        break

            return found_right, position_right

        def _mark_brackets(self, cursor, left_pos, right_pos):
            '''Highlight found brackets.'''

            hl_format = QtGui.QTextCharFormat()
            color = self.config_theme.get('editor', 'brackets_color')

            cursor.setPosition(left_pos)
            cursor.movePosition(QtGui.QTextCursor.NextCharacter,
                                QtGui.QTextCursor.KeepAnchor)
            hl_format.setForeground(QtGui.QColor(color))
            self._left_selected_bracket.format = hl_format
            self._left_selected_bracket.cursor = cursor

            cursor.setPosition(right_pos - 1)
            cursor.movePosition(QtGui.QTextCursor.NextCharacter,
                                QtGui.QTextCursor.KeepAnchor)
            hl_format.setForeground(QtGui.QColor(color))
            self._right_selected_bracket.format = hl_format
            self._right_selected_bracket.cursor = cursor
            return

        def _toggle_casts(self):
            '''TODO: feature to toggle casting.'''

            print 'toggle 0'
            if self._casts_marked:
                for selection in self._casts_selections:
                    selection.cursor.clearSelection()
                self._casts_marked = False
                self._casts_selections = None
                return
            print 'toggle 1'
            search_flag = QtGui.QTextDocument.FindFlags(0)
            search_flag |= QtGui.QTextDocument.FindWholeWords
            search_flag |= QtGui.QTextDocument.FindCaseSensitively
            marker_color = self.config_theme.get('editor', 'hidden_color')

            self._casts_selections = []
            selection = QTextEdit.ExtraSelection()

            cursor = self.document().find(QtCore.QRegExp(r'\(\w+\s\*\)'))
            cursor.select(QtGui.QTextCursor.WordUnderCursor)
            print cursor.block().text()

            cursor.movePosition(QtGui.QTextCursor.Start)

            selection.format.setBackground(QtGui.QColor(marker_color))
            selection.cursor = cursor
            self._casts_selections.append(selection)

            while cursor:
                cursor = self.document().find(QtCore.QRegExp(r'\(\w+\s\*\)'),
                                              cursor, search_flag)
                if not cursor:
                    break
                selection = QTextEdit.ExtraSelection()
                selection.format.setBackground(QtGui.QColor(marker_color))
                selection.cursor = cursor
                print cursor.block().text()
                self._casts_selections.append(selection)
            self.setExtraSelections(self._casts_selections)
            self._casts_marked = True
            return

        def _highlight_indents(self, event):
            '''Highlight indents.'''

            if not self.config_main.getboolean('editor', 'show_indent_guides'):
                return

            # Get doc and viewport
            doc = self.document()
            viewport = self.viewport()

            # Multiplication factor and indent width
            indent_width = self.config_theme.getint('editor', 'indent_width')

            # Init painter
            painter = QtGui.QPainter()
            painter.begin(viewport)

            # Prepare pen
            indent_color = self.config_theme.get('editor', 'indent_color')
            pen = QtGui.QPen(indent_color)
            pen.setStyle(QtCore.Qt.DotLine)
            painter.setPen(pen)
            offset = doc.documentMargin() + self.contentOffset().x()

            def paint_indentation_guides(cursor):
                '''Paint indentation guides.'''

                _y3 = self.cursorRect(cursor).top()
                _y4 = self.cursorRect(cursor).bottom()

                text = cursor.block().text()
                indentation = self.tools.get_tabs(text)
                for _x0 in range(indent_width, indentation, indent_width):
                    _w0 = self.fontMetrics().width('i' * _x0) + offset
                    # if scrolled horizontally it can become < 0
                    if _w0 > 0:
                        painter.drawLine(_w0, _y3, _w0, _y4)

            self._do_for_visible_blocks(paint_indentation_guides)

            painter.end()
            return

        def _do_for_visible_blocks(self, function):
            ''' _do_for_visible_blocks(function)

            Call the given function(cursor) for all blocks that are currently
            visible. This is used by several appearence extensions that
            paint per block.

            The supplied cursor will be located at the beginning of each block.
            This cursor may be modified by the function as required

            '''

            # Start cursor at top line.
            cursor = self.cursorForPosition(QtCore.QPoint(0, 0))
            cursor.movePosition(cursor.StartOfBlock)

            while True:
                # Call the function with a copy of the cursor
                function(QtGui.QTextCursor(cursor))

                # Go to the next block (or not if we are done)
                if self.cursorRect(cursor).bottom() > self.height():
                    # Reached end of the repaint area
                    break
                if not cursor.block().next().isValid():
                    # Reached end of the text
                    break
                cursor.movePosition(cursor.NextBlock)
            return

        def _create_menu(self):
            '''TODO: Create right click context menu.'''

            action = QtGui.QAction("Toggle casts", self)
            action.triggered.connect(self._toggle_casts)
            self.addAction(action)
            return

        def document_is_loaded(self, boolean):
            '''Indicate whether document is loaded.'''
            self._loaded = boolean
            return

    def __init__(self, plugin, *args):

        QFrame.__init__(self, *args)
        self.plugin = plugin
        self.config_main = self.plugin.config_main
        self.config_theme = self.plugin.config_theme
        self.tools = self.plugin.tools

        self.setFrameStyle(QFrame.StyledPanel | QFrame.Plain)

        self.edit = self.PlainTextEdit(self)
        self.number_bar = self.NumberBar(self.config_theme, self.edit)

        hbox = QHBoxLayout(self)
        hbox.setSpacing(0)
        hbox.addWidget(self.number_bar)
        hbox.addWidget(self.edit)

        self.edit.blockCountChanged.connect(self.number_bar.adjust_width)
        self.edit.updateRequest.connect(self.number_bar.update_contents)
        QtGui.QShortcut(QtGui.QKeySequence("Ctrl+S"), self).\
            activated.connect(self.save_file)
        QtGui.QShortcut(QtGui.QKeySequence("Ctrl+F"), self).\
            activated.connect(self.show_find)
        return

    def save_file(self):
        '''Save file'''
        self.tools.save_file(data=self.edit.toPlainText())
        return

    def show_find(self):
        '''Shows find and replace modial dialog.'''
        Find(self).show()
        return

    def text_cursor(self):
        '''Wrapper for textCursor method.'''
        return self.edit.textCursor()

    def set_text_cursor(self, cursor):
        '''Wrapper for setTextCursor method.'''
        return self.edit.setTextCursor(cursor)

    def move_cursor(self, mode):
        '''Wrapper for moveCursor method.'''
        return self.edit.moveCursor(mode)

    def toPlainText(self):
        '''Wrapper for toPlainText method.'''
        return self.edit.toPlainText()

    def set_loaded(self, boolean):
        '''Set boolean flag whether document is loaded.'''
        self.edit.document_is_loaded(boolean)
        return

    def insert_plain_text(self, text):
        '''Wrapper to call insertPlainText.'''
        self.edit.insertPlainText(text)

    def document(self):
        '''Wrapper to return document.'''
        return self.edit.document()


class EditorForm(object):
    '''This ugly class is mostly auto-generated, so I dont touch it.'''

    def __init__(self, config_main, config_theme, tools, *args):
        super(EditorForm, self).__init__()
        self.config_main = config_main
        self.config_theme = config_theme
        self.tools = tools
        return

    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(800, 600)
        self.gridLayout = QtGui.QGridLayout(Form)
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        self.gridLayout.setVerticalSpacing(0)
        self.gridLayout.setObjectName("gridLayout")
        self.plainTextEdit = LNTextEdit(self, Form)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.plainTextEdit.sizePolicy().hasHeightForWidth())
        self.plainTextEdit.setSizePolicy(sizePolicy)
        self.plainTextEdit.setFrameShape(QtGui.QFrame.NoFrame)
        self.plainTextEdit.setFrameShadow(QtGui.QFrame.Plain)
        self.plainTextEdit.setObjectName("plainTextEdit")
        self.gridLayout.addWidget(self.plainTextEdit, 0, 0, 1, 1)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        Form.setWindowTitle(QtGui.QApplication.translate("Form", "Form", None, QtGui.QApplication.UnicodeUTF8))


# https://www.binpress.com/tutorial/building-a-text-editor-with-pyqt-part-3/147
class Find(QtGui.QDialog):
    '''Implements find-replace functionality.'''
    def __init__(self, parent=None):
        QtGui.QDialog.__init__(self, parent)
        self.parent = parent
        self.last_start = 0
        self.initUI()

    def initUI(self):
        '''Initialise interface.'''

        find_button = QtGui.QPushButton("Find", self)
        find_button.clicked.connect(self._find)

        replace_button = QtGui.QPushButton("Replace", self)
        replace_button.clicked.connect(self._replace)

        all_button = QtGui.QPushButton("Replace all", self)
        all_button.clicked.connect(self._replace_all)

        self.normal_radio = QtGui.QRadioButton("Normal", self)

        regexp_radio = QtGui.QRadioButton("RegEx", self)

        # The field into which to type the query
        self.find_field = QtGui.QTextEdit(self)
        self.find_field.resize(250, 10)

        # The field into which to type the text to replace the
        # queried text
        self.replace_field = QtGui.QTextEdit(self)
        self.replace_field.resize(250, 10)

        layout = QtGui.QGridLayout()

        layout.addWidget(self.find_field, 1, 0, 1, 4)
        layout.addWidget(self.normal_radio, 2, 2)
        layout.addWidget(regexp_radio, 2, 3)
        layout.addWidget(find_button, 2, 0, 1, 2)

        layout.addWidget(self.replace_field, 3, 0, 1, 4)
        layout.addWidget(replace_button, 4, 0, 1, 2)
        layout.addWidget(all_button, 4, 2, 1, 2)

        self.setGeometry(300, 300, 360, 250)
        self.setWindowTitle("Find and Replace")
        self.setLayout(layout)

        self.normal_radio.setChecked(True)

    def _find(self):
        '''Find text.'''

        text = self.parent.toPlainText()
        query = self.find_field.toPlainText()

        if self.normal_radio.isChecked():
            self.last_start = text.find(query, self.last_start + 1)

            # If the find() method didn't return -1 (not found)
            if self.last_start >= 0:
                end = self.last_start + len(query)
                self._move_cursor(self.last_start, end)
            else:
                # Make the next search start from the begining again
                self.last_start = 0
                self.parent.move_cursor(QtGui.QTextCursor.End)
        else:
            pattern = re.compile(query)
            match = pattern.search(text, self.last_start + 1)

            if match:
                self.last_start = match.start()
                self._move_cursor(self.last_start, match.end())
            else:
                self.last_start = 0
                # We set the cursor to the end if the search was unsuccessful
                self.parent.move_cursor(QtGui.QTextCursor.End)

    def _replace(self):
        '''Replace found text.'''

        cursor = self.parent.text_cursor()
        if cursor.hasSelection():
            # We insert the new text, which will override the selected
            # text
            cursor.insertText(self.replace_field.toPlainText())
            self.parent.set_text_cursor(cursor)

    def _replace_all(self):
        '''Replace all found matches.'''

        self.last_start = 0
        self.find()
        while self.last_start:
            self.replace()
            self.find()

    def _move_cursor(self, start, end):
        '''Move cursor.'''

        cursor = self.parent.text_cursor()
        cursor.setPosition(start)
        # Next we move the Cursor by over the match and pass the KeepAnchor parameter
        # which will make the cursor select the the match's text
        cursor.movePosition(QtGui.QTextCursor.Right,
                            QtGui.QTextCursor.KeepAnchor,
                            end - start)
        self.parent.set_text_cursor(cursor)
        return


class Canvas(idaapi.PluginForm):
    '''Implements main GUI class.'''
    def __init__(self, config_main, config_theme, tools, window_name):
        idaapi.PluginForm.__init__(self)
        self.config_main = config_main
        self.config_theme = config_theme
        self.tools = tools
        self.window_name = window_name

        self.interface = None
        self.parent = None
        return

    def OnCreate(self, form):
        '''Called when the plugin form is created.'''

        self.parent = self.FormToPySideWidget(form)
        self.interface = EditorForm(self.config_main,
                                    self.config_theme,
                                    self.tools)

        self.interface.setupUi(self.parent)
        self.parent.setLayout(self.interface.gridLayout)

        text_palette = self.interface.plainTextEdit.palette()
        color = QtGui.QColor(self.config_theme.get('editor',
                                                   'background_color'))
        text_palette.setColor(QtGui.QPalette.Active,
                              QtGui.QPalette.Base, color)
        text_palette.setColor(QtGui.QPalette.Inactive,
                              QtGui.QPalette.Base, color)
        self.interface.plainTextEdit.setPalette(text_palette)
        self.parent.setWindowTitle(self.window_name)

    def OnClose(self, form):
        '''Called when the plugin form is closed.'''
        self.tools.save_file(data=self.interface.plainTextEdit.toPlainText())
        return

    def add_text(self, text):
        '''Add text to document.'''
        self.interface.plainTextEdit.insert_plain_text(text)
        return

    def set_loaded(self, boolean):
        '''Set flag indicating that document load has finished.'''
        self.interface.plainTextEdit.set_loaded(boolean)
        return

    def highlight_document(self, token_kinds):
        '''Switch on document highlighting.'''
        include.syntax.Highlighter(self.interface.plainTextEdit.document(),
                                   self.config_theme,
                                   token_kinds)
        return
