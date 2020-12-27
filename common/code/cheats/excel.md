# Extract

```bash
atool --format=zip -x foo.xlsx
find . -type f -iname '*.xml' -print0 | xargs -0 -I{} tidy -m -q -xml --indent auto --indent-spaces 4 --vertical-space yes --tidy-mark no {}
```

# Validation

### Data

Global: Home tab > Editing group > Find & Select > Data Validation
Local: Select: one or more cells > Data tab > Data Tools group > Data Validation

https://www.ablebits.com/office-addins-blog/2017/08/16/data-validation-excel/#find-data-validation

### Formulas

- ./xl/worksheets/sheet1.xml
    - XPath: `//conditionalFormatting[sqref]/cfRule/formula`
        - sqref: "$column_foo_first_line:$column_foo_last_line"

# Date Format

- Formula: `=DATE(2020,05,31)`
- On cell: Context Menu > Format Cells... > Number tab > Custom > Type: dd/mm/yyyy 
- Validation: Home tab > Number group > Dropdown value: Custom

# Hidden Sheets

- ./xl/workbook.xml
    ```xml
    <sheet name="Foo" sheetId="1" state="hidden" r:id="rId2" />
    ```

# Schema

https://docs.microsoft.com/en-us/office/open-xml/structure-of-a-spreadsheetml-document
