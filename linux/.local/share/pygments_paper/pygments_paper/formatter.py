"""
    pygments.formatters.paper
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    Paper formatter for terminal output with ANSI sequences.

    :copyright: Copyright 2006-2022 by the Pygments team, see AUTHORS.
    :license: BSD, see LICENSE for details.
"""

from pygments.formatters.terminal import TerminalFormatter
from pygments.token import Comment, Error, Escape, Generic, Keyword, Literal, Name, Number, Operator, Other, Punctuation, String, Text, Token, Whitespace
from pygments.console import ansiformat
from pygments.util import get_choice_opt


__all__ = ['PaperTerminalFormatter']


#: Map token types to a tuple of color values for light and dark
#: backgrounds.
TERMINAL_COLORS = {
    Comment:                ('green','green'),
    Comment.Hashbang:       ('green','green'),
    Comment.Multiline:      ('green','green'),
    Comment.Preproc:        ('magenta','magenta'),
    Comment.PreprocFile:    ('green','green'),
    Comment.Single:         ('green','green'),
    Comment.Special:        ('*green*','*green*'),

    Error:                  ('_red_','_red_'),

    Escape:                 ('white','black'),

    Generic:                ('white','black'),
    Generic.Deleted:        ('red','red'),
    Generic.Emph:           ('',''),
    Generic.EmphStrong:     ('**','**'),
    Generic.Error:          ('red','red'),
    Generic.Heading:        ('**','**'),
    Generic.Inserted:       ('green','green'),
    Generic.Output:         ('white','black'),
    Generic.Prompt:         ('*blue*','*blue*'),
    Generic.Strong:         ('**','**'),
    Generic.Subheading:     ('underline','underline'),
    Generic.Traceback:      ('blue','blue'),

    Keyword:                ('*yellow*','*yellow*'),
    Keyword.Constant:       ('cyan','cyan'),
    Keyword.Declaration:    ('blue','blue'),
    Keyword.Namespace:      ('magenta','magenta'),
    Keyword.Pseudo:         ('magenta','magenta'),
    Keyword.Reserved:       ('magenta','magenta'),
    Keyword.Type:           ('yellow','yellow'),

    Literal:                ('*magenta*','*magenta*'),
    Literal.Date:           ('*magenta*','*magenta*'),

    Name.Attribute:         ('*blue*','*blue*'),
    Name.Builtin:           ('*blue*','*blue*'),
    Name.Builtin.Pseudo:    ('*blue*','*blue*'),
    Name.Class:             ('*blue*','*blue*'),
    Name.Constant:          ('*cyan*','*cyan*'),
    Name.Decorator:         ('*blue*','*blue*'),
    Name.Entity:            ('*blue*','*blue*'),
    Name.Exception:         ('*red*','*red*'),
    Name.Function:          ('*cyan*','*cyan*'),
    Name.Function.Magic:    ('*cyan*','*cyan*'),
    Name.Label:             ('*blue*','*blue*'),
    Name.Namespace:         ('*blue*','*blue*'),
    Name.Other:             ('*blue*','*blue*'),
    Name.Tag:               ('*blue*','*blue*'),
    Name.Variable:          ('*magenta*','*magenta*'),
    Name.Variable.Class:    ('*magenta*','*magenta*'),
    Name.Variable.Global:   ('*magenta*','*magenta*'),
    Name.Variable.Instance: ('*magenta*','*magenta*'),
    Name.Variable.Magic:    ('*magenta*','*magenta*'),

    Number:                 ('*magenta*','*magenta*'),
    Number.Bin:             ('*magenta*','*magenta*'),
    Number.Float:           ('*magenta*','*magenta*'),
    Number.Hex:             ('*magenta*','*magenta*'),
    Number.Integer:         ('*magenta*','*magenta*'),
    Number.Integer.Long:    ('*magenta*','*magenta*'),
    Number.Oct:             ('*magenta*','*magenta*'),

    Operator:               ('yellow','yellow'),
    Operator.Word:          ('green','green'),

    Other:                  ('white','black'),

    Punctuation:            ('white','black'),
    Punctuation.Marker:     ('white','black'),

    String.Affix:           ('magenta','magenta'),
    String.Backtick:        ('magenta','magenta'),
    String.Char:            ('magenta','magenta'),
    String:                 ('magenta','magenta'),
    String.Delimiter:       ('magenta','magenta'),
    String.Doc:             ('magenta','magenta'),
    String.Double:          ('magenta','magenta'),
    String.Escape:          ('magenta','magenta'),
    String.Heredoc:         ('magenta','magenta'),
    String.Interpol:        ('magenta','magenta'),
    String.Other:           ('magenta','magenta'),
    String.Regex:           ('magenta','magenta'),
    String.Single:          ('magenta','magenta'),
    String.Symbol:          ('magenta','magenta'),

    Text:                   ('',''),

    Token:                  ('',''),

    Whitespace:             ('black','white'),
}

class PaperTerminalFormatter(TerminalFormatter):
    name = 'PaperTerminal'
    aliases = ['paper']
    filenames = []

    def __init__(self, **options):
        TerminalFormatter.__init__(self, **options)
        self.colorscheme = options.get('colorscheme', None) or TERMINAL_COLORS
