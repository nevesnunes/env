# Validations

### Data Validation

Global: Home tab > Editing group > Find & Select > Data Validation
Local: Select: one or more cells > Data tab > Data Tools group > Data Validation

https://www.ablebits.com/office-addins-blog/2017/08/16/data-validation-excel/#find-data-validation

### Formulas

```bash
atool --format=zip -x foo.xlsx
```

foo/xl/worksheets/sheet1.xml
    XPath: //conditionalFormatting[sqref]/cfRule/formula
        sqref: "$column_foo_first_line:$column_foo_last_line"

# date format

Formula: =DATE(2020,05,31)
On cell: Context Menu > Format Cells... > Number tab > Custom > Type: dd/mm/yyyy 
Validation: Home tab > Number group > Dropdown value: Custom


