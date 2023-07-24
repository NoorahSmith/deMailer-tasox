import os

# System call
os.system("")

# Class of different variables
class global_variable():
    OS_SEP = os.sep
    COLUMN_WIDTH_MULTIPLIER = 9
    TABULATE_TABLE_FORMAT = "fancy_grid"
    EMAIL_FILENAME = ""
    CWD = os.getcwd()
    OUTPUT_TO_HTML_REPORT = "" # This variable will be changed by printd.tabulateToHtml() after the creation of the HTML report
    EMAIL_ATTACHMENTS_FULL_PATH = [] # This variable will be changed by extractor.extractBody() after extracting the attachment from the email
    EMAIL_BODY_TO_TEXT_FULL_PATH = "" # This variable will be changed by converter.body2txx() after extracting the attachment from the email