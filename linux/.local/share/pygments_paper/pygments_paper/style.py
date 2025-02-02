"""
    pygments.styles.paper
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    Paper style adapted from Solarized by Camil Staps
    See: https://github.com/altercation/solarized

    :copyright: Copyright 2006-2022 by the Pygments team, see AUTHORS.
    :license: BSD, see LICENSE for details.
"""

from pygments.style import Style
from pygments.token import Comment, Error, Escape, Generic, Keyword, Literal, Name, Number, Operator, Other, Punctuation, String, Text, Token, Whitespace

def make_style(colors):
    return {
        Comment:                'italic ' + colors['green'],
        Comment.Hashbang:       colors['green'],
        Comment.Multiline:      colors['green'],
        Comment.Preproc:        'noitalic ' + colors['magenta'],
        Comment.PreprocFile:    'noitalic ' + colors['green'],
        Comment.Single:         'italic ' + colors['green'],
        Comment.Special:        'bold italic ' + colors['green'],

        Error:                  'bg:' + colors['red'],

        Escape:                 colors['fg'],

        Generic:                colors['fg'],
        Generic.Deleted:        colors['red'],
        Generic.Emph:           'italic',
        Generic.EmphStrong:     'bold italic',
        Generic.Error:          colors['red'],
        Generic.Heading:        'bold',
        Generic.Inserted:       colors['green'],
        Generic.Output:         colors['fg'],
        Generic.Prompt:         'bold ' + colors['blue'],
        Generic.Strong:         'bold',
        Generic.Subheading:     'underline',
        Generic.Traceback:      colors['blue'],

        Keyword:                'bold ' + colors['yellow'],
        Keyword.Constant:       colors['cyan'],
        Keyword.Declaration:    colors['blue'],
        Keyword.Namespace:      colors['magenta'],
        Keyword.Pseudo:         colors['magenta'],
        Keyword.Reserved:       colors['magenta'],
        Keyword.Type:           colors['yellow'],

        Literal:                'bold ' + colors['magenta'],
        Literal.Date:           'bold ' + colors['magenta'],

        Name.Attribute:         'bold ' + colors['blue'],
        Name.Builtin:           'bold ' + colors['blue'],
        Name.Builtin.Pseudo:    'bold ' + colors['blue'],
        Name.Class:             'bold ' + colors['blue'],
        Name.Constant:          'bold ' + colors['cyan'],
        Name.Decorator:         'bold ' + colors['blue'],
        Name.Entity:            'bold ' + colors['blue'],
        Name.Exception:         'bold ' + colors['red'],
        Name.Function:          'bold ' + colors['cyan'],
        Name.Function.Magic:    'bold ' + colors['cyan'],
        Name.Label:             'bold ' + colors['blue'],
        Name.Namespace:         'bold ' + colors['blue'],
        Name.Other:             'bold ' + colors['blue'],
        Name.Tag:               'bold ' + colors['blue'],
        Name.Variable:          'bold ' + colors['magenta'],
        Name.Variable.Class:    'bold ' + colors['magenta'],
        Name.Variable.Global:   'bold ' + colors['magenta'],
        Name.Variable.Instance: 'bold ' + colors['magenta'],
        Name.Variable.Magic:    'bold ' + colors['magenta'],

        Number:                 'bold ' + colors['magenta'],
        Number.Bin:             'bold ' + colors['magenta'],
        Number.Float:           'bold ' + colors['magenta'],
        Number.Hex:             'bold ' + colors['magenta'],
        Number.Integer:         'bold ' + colors['magenta'],
        Number.Integer.Long:    'bold ' + colors['magenta'],
        Number.Oct:             'bold ' + colors['magenta'],

        Operator:               colors['yellow'],
        Operator.Word:          colors['green'],

        Other:                  colors['fg'],

        Punctuation:            colors['fg'],
        Punctuation.Marker:     colors['fg'],

        String.Affix:           colors['magenta'],
        String.Backtick:        colors['magenta'],
        String.Char:            colors['magenta'],
        String:                 colors['magenta'],
        String.Delimiter:       colors['magenta'],
        String.Doc:             colors['magenta'],
        String.Double:          colors['magenta'],
        String.Escape:          colors['magenta'],
        String.Heredoc:         colors['magenta'],
        String.Interpol:        colors['magenta'],
        String.Other:           colors['magenta'],
        String.Regex:           colors['magenta'],
        String.Single:          colors['magenta'],
        String.Symbol:          colors['magenta'],

        Text:                   colors['fg'],

        Token:                  colors['fg'],

        Whitespace:             colors['bg'],
    }


DARK_COLORS = {
    'bg':      '#281830',
    'fg':      '#dddde8',
    'grey':    '#403448',
    'red':     '#c62a45',
    'green':   '#2e5f0b',
    'yellow':  '#622e04',
    'blue':    '#4e6cd0',
    'magenta': '#804fa1',
    'cyan':    '#05505d',
}

LIGHT_COLORS = {
    'bg':      '#dddde8',
    'fg':      '#281830',
    'grey':    '#403448',
    'red':     '#c62a45',
    'green':   '#2e5f0b',
    'yellow':  '#622e04',
    'blue':    '#4e6cd0',
    'magenta': '#804fa1',
    'cyan':    '#05505d',
}


class PaperDarkStyle(Style):
    styles = make_style(DARK_COLORS)
    background_color = DARK_COLORS['bg']
    highlight_color = DARK_COLORS['bg']
    line_number_color = DARK_COLORS['grey']
    line_number_background_color = DARK_COLORS['bg']


class PaperLightStyle(PaperDarkStyle):
    styles = make_style(LIGHT_COLORS)
    background_color = LIGHT_COLORS['bg']
    highlight_color = LIGHT_COLORS['bg']
    line_number_color = LIGHT_COLORS['grey']
    line_number_background_color = LIGHT_COLORS['bg']
