from sys import stderr
from docx import Document

from instruments import *
from config import *


if __name__ == '__main__':
    try:
        document = Document()
        package_list = read_package_in_file(INITIAL_FILE)
        table = generate_doc_table(document)
        run_check(table, package_list)
        set_col_widths(table)
        document.save(RESULT_FILE)
    except Exception as er:
        print(er, file=stderr)
