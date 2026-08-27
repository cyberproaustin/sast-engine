"""A credential word narrows what a value is for; the value still decides what it is."""


class Config:
    pass


app = Config()
app.config = {}

# POSITIVE. The value is capable of serving as a signing credential, and the compound
# configuration key says that is what this program relies on it for.
app.config["SECRET_KEY"] = "s3cr3t-dev-key"

# POSITIVE. A suffix does not change the role of the value. Configuration keys are
# compound, so the credential term must be a word rather than the whole identifier.
app.config["JWT_SECRET_KEY_V2"] = "am0r3C0mpl3xK3y"

# POSITIVE. Camel case is another identifier boundary, and the mixed-case value can be
# used as the same signing credential as the two subscript forms.
app.secretKey = "F12Zr47j yX@H!jmM"

ctx = {}

# NEGATIVE. This is healthchecks' measured case. The key describes what the status is
# about, while the value is the closed status word rendered into a CSS class.
ctx["email_password_status"] = "success"

# NEGATIVE. Even the exact identifier cannot turn a status into a credential. The name
# narrows the question; the value still answers it.
ctx["password"] = "success"

glyphs = Config()

# NEGATIVE. This is pdfjs' measured case. The Adobe glyph name for U+3299 merely contains
# the letters "secret", with no identifier boundary and no credential role.
glyphs.ideographicsecretcircle = 0x3299
